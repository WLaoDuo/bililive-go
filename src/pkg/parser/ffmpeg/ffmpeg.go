package ffmpeg

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/hr3lxphr6j/bililive-go/src/instance"
	"github.com/hr3lxphr6j/bililive-go/src/live"
	"github.com/hr3lxphr6j/bililive-go/src/pkg/parser"
	"github.com/hr3lxphr6j/bililive-go/src/pkg/utils"
)

const (
	Name = "ffmpeg"

	userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36"
)

func init() {
	parser.Register(Name, new(builder))
}

type builder struct{}

func (b *builder) Build(cfg map[string]string) (parser.Parser, error) {
	debug := false
	if debugFlag, ok := cfg["debug"]; ok && debugFlag != "" {
		debug = true
	}
	return &Parser{
		debug:       debug,
		closeOnce:   new(sync.Once),
		statusReq:   make(chan struct{}, 1),
		statusResp:  make(chan map[string]string, 1),
		timeoutInUs: cfg["timeout_in_us"],
	}, nil
}

type Parser struct {
	cmd         *exec.Cmd
	cmdStdIn    io.WriteCloser
	cmdStdout   io.ReadCloser
	closeOnce   *sync.Once
	debug       bool
	timeoutInUs string

	statusReq  chan struct{}
	statusResp chan map[string]string
	cmdLock    sync.Mutex
}

func (p *Parser) scanFFmpegStatus() <-chan []byte {
	ch := make(chan []byte)
	br := bufio.NewScanner(p.cmdStdout)
	br.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}

		if idx := bytes.Index(data, []byte("progress=continue\n")); idx >= 0 {
			return idx + 1, data[0:idx], nil
		}

		return 0, nil, nil
	})
	go func() {
		defer close(ch)
		for br.Scan() {
			ch <- br.Bytes()
		}
	}()
	return ch
}

func (p *Parser) decodeFFmpegStatus(b []byte) (status map[string]string) {
	status = map[string]string{
		"parser": Name,
	}
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Split(bufio.ScanLines)
	for s.Scan() {
		split := bytes.SplitN(s.Bytes(), []byte("="), 2)
		if len(split) != 2 {
			continue
		}
		status[string(bytes.TrimSpace(split[0]))] = string(bytes.TrimSpace(split[1]))
	}
	return
}

func (p *Parser) scheduler() {
	defer close(p.statusResp)
	statusCh := p.scanFFmpegStatus()
	for {
		select {
		case <-p.statusReq:
			select {
			case b, ok := <-statusCh:
				if !ok {
					return
				}
				p.statusResp <- p.decodeFFmpegStatus(b)
			case <-time.After(time.Second * 3):
				p.statusResp <- nil
			}
		default:
			if _, ok := <-statusCh; !ok {
				return
			}
		}
	}
}

func (p *Parser) Status() (map[string]string, error) {
	// TODO: check parser is running
	p.statusReq <- struct{}{}
	return <-p.statusResp, nil
}

func (p *Parser) ParseLiveStream(ctx context.Context, streamUrlInfo *live.StreamUrlInfo, live live.Live, file string) (err error) {
	url := streamUrlInfo.Url
	ffmpegPath, err := utils.GetFFmpegPath(ctx)
	if err != nil {
		return err
	}
	headers := streamUrlInfo.HeadersForDownloader
	ffUserAgent, exists := headers["User-Agent"]
	if !exists {
		ffUserAgent = userAgent
	}
	referer, exists := headers["Referer"]
	if !exists {
		referer = live.GetRawUrl()
	}

	inst := instance.GetInstance(ctx)
	args := []string{
		"-copyts",
		"-nostats",
		"-progress", "-",
		"-y",
		// "-re",
		"-user_agent", "'" + ffUserAgent + "'",
		"-referer", "'" + referer + "'",
		"-rw_timeout", p.timeoutInUs,
		"-i", url.String(),
		"-c", "copy", //所有流(视频、音频、字幕等) copy
		// "-c:a", "copy", //对audio流使用 copy
		// "-c:v", "copy", //对video流使用 copy
		"-rtbufsize", "30M", //实时缓冲区，默认3M
		// "-max_delay", "700000", //最大延迟700000us
		// "-bsf:a", "aac_adtstoasc",
	}
	daili := inst.Config.Proxy
	if daili != "" {
		args = []string{
			"-http_proxy", daili,
			"-copyts",        //复制时间戳
			"-nostats",       //-nostats 可以让终端输出更加简洁,只显示必要的信息
			"-progress", "-", //-progress - 可以实时显示转码进度
			"-y", //-y 可以自动覆盖已存在的输出文件,无需手动确认。
			// "-re", //
			"-user_agent", "'" + ffUserAgent + "'",
			"-referer", "'" + referer + "'",
			"-i", url.String(),
			"-c", "copy", //所有流(视频、音频、字幕等) copy
			// "-c:a", "copy", //对audio流使用 copy
			// "-c:v", "copy", //对video流使用 copy
			"-rtbufsize", "30M", //实时缓冲区，默认3M
			// "-max_delay", "700000", //最大延迟700000 us
		}
	}
	for k, v := range headers {
		if k == "User-Agent" || k == "Referer" {
			continue
		}
		args = append(args, "-headers", k+": "+v)
	}

	MaxFileSize := inst.Config.VideoSplitStrategies.MaxFileSize
	if MaxFileSize < 0 {
		inst.Logger.Infof("Invalid MaxFileSize: %d", MaxFileSize)
	} else if MaxFileSize > 0 {
		args = append(args, "-fs", strconv.Itoa(MaxFileSize))
	}

	args = append(args, file) //增加输出文件路径名参数
	// fmt.Println("最终执行命令", args)
	inst.Logger.Info(args)

	// p.cmd operations need p.cmdLock
	func() {
		p.cmdLock.Lock()
		defer p.cmdLock.Unlock()
		p.cmd = exec.Command(ffmpegPath, args...)
		fmt.Println("p.cmd:", p.cmd)
		if p.cmdStdIn, err = p.cmd.StdinPipe(); err != nil {
			return
		}
		if p.cmdStdout, err = p.cmd.StdoutPipe(); err != nil {
			return
		}
		if p.debug {
			p.cmd.Stderr = os.Stderr
		}
		if err = p.cmd.Start(); err != nil {
			if p.cmd.Process != nil {
				p.cmd.Process.Kill()
			}
			return
		}
	}()
	if err != nil {
		return err
	}

	go p.scheduler()
	err = p.cmd.Wait()
	if err != nil {
		return err
	}
	return nil
}

func (p *Parser) Stop() (err error) {
	p.closeOnce.Do(func() {
		p.cmdLock.Lock()
		defer p.cmdLock.Unlock()
		if p.cmd != nil && p.cmd.ProcessState == nil {
			if p.cmdStdIn != nil && p.cmd.Process != nil {
				if _, err = p.cmdStdIn.Write([]byte("q")); err != nil {
					err = fmt.Errorf("error sending stop command to ffmpeg: %v", err)
				}
			} else if p.cmdStdIn == nil {
				err = fmt.Errorf("p.cmdStdIn == nil")
			} else if p.cmd.Process == nil {
				err = fmt.Errorf("p.cmd.Process == nil")
			}
		}
	})
	return err
}
