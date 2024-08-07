package stripchat

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hr3lxphr6j/bililive-go/src/configs"
	"github.com/hr3lxphr6j/bililive-go/src/live"
	"github.com/hr3lxphr6j/bililive-go/src/live/internal"
	"github.com/hr3lxphr6j/bililive-go/src/pkg/utils"
	"github.com/parnurzeal/gorequest"
	"github.com/tidwall/gjson"
)

func get_modelId(modleName string, daili string) string {
	fmt.Println("主播名字：", modleName)
	request := gorequest.New()
	if daili != "" {
		request = request.Proxy(daili) //代理
	}

	// 添加头部信息
	request.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	request.Set("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
	request.Set("Accept-Encoding", "gzip, deflate")
	request.Set("Upgrade-Insecure-Requests", "1")
	request.Set("Sec-Fetch-Dest", "document")
	request.Set("Sec-Fetch-Mode", "navigate")
	request.Set("Sec-Fetch-Site", "none")
	request.Set("Sec-Fetch-User", "?1")
	request.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0")
	// request.Set("If-Modified-Since", "Mon, 29 Jul 2024 08:41:12 GMT")
	request.Set("Te", "trailers")
	request.Set("Connection", "close")

	// 发起 GET 请求
	_, body, errs := request.Get("https://zh.stripchat.com/api/front/v2/models/username/" + modleName + "/chat").End()

	// 处理响应
	if len(errs) > 0 {
		fmt.Println("请求modelID出错:", body, errs)
		return "false"
	} else {
		// 解析 JSON 响应
		if (len(gjson.Get(body, "messages").String())) > 2 {
			modelId := gjson.Get(body, "messages.0.modelId").String()
			return modelId
		} else {
			return "OffLine"
		}
	}
}

func get_M3u8(modelId string, daili string) string {
	// fmt.Println(modelId)
	// url := "https://edge-hls.doppiocdn.com/hls/" + modelId + "/master/" + modelId + "_auto.m3u8?playlistType=lowLatency"
	url := "https://edge-hls.doppiocdn.com/hls/" + modelId + "/master/" + modelId + "_auto.m3u8"
	request := gorequest.New()
	if daili != "" {
		request = request.Proxy(daili) //代理
	}
	resp, body, errs := request.Get(url).End()

	if errs != nil {
		fmt.Println("出错详情 modeId=", modelId)
		for _, err := range errs {
			if err == io.EOF {
				// 处理 EOF 错误
				fmt.Println("Got EOF error")
			} else {
				// 其他错误处理
				fmt.Println("Error:", err)
			}
		}
	}

	if modelId == "false" || modelId == "OffLine" || resp.StatusCode != 200 || len(errs) > 0 {

		return "false"
	} else {
		// fmt.Println((body))
		// re := regexp.MustCompile(`(https:\/\/[\w\-\.]+\/hls\/[\d]+\/[\d\_p]+\.m3u8\?playlistType=lowLatency)`)
		re := regexp.MustCompile(`(https:\/\/[\w\-\.]+\/hls\/[\d]+\/[\d\_p]+\.m3u8)`)

		matches := re.FindString(body)
		return matches
	}
}
func test_m3u8(url string, daili string) bool {
	request := gorequest.New()
	if daili != "" {
		request = request.Proxy(daili) //代理
	}
	resp, body, errs := request.Get(url).End()
	if url == "false" || len(errs) > 0 || resp.StatusCode != 200 {
		return false
	}
	if resp.StatusCode == 200 {
		_ = body
		// fmt.Println(body)
		return true
	}
	return false
}

const (
	domain = "zh.stripchat.com"
	cnName = "stripchat"
)

type Live struct {
	internal.BaseLive
}

func init() {
	live.Register(domain, new(builder))
}

type builder struct{}

func (b *builder) Build(url *url.URL, opt ...live.Option) (live.Live, error) {
	return &Live{
		BaseLive: internal.NewBaseLive(url, opt...),
	}, nil
}

func getConfigBesidesExecutable() (*configs.Config, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(filepath.Dir(exePath), "config.yml")
	config, err := configs.ReadConfigWithFile(configPath)
	if err != nil {
		return nil, err
	}
	return config, nil
}
func GetProxy() string {
	daili := ""
	read_config, err := getConfigBesidesExecutable()
	if err == nil {
		// fmt.Println("daili:", read_config.Proxy)
		daili = read_config.Proxy
		return daili
	} else {
		daili = ""
		return daili
		// fmt.Println("err:", err)
	}
}

func (l *Live) GetInfo() (info *live.Info, err error) {

	modeName := strings.Split(l.Url.String(), "/")
	modelName := modeName[len(modeName)-1]
	daili := GetProxy()
	modelID := get_modelId(modelName, daili)
	m3u8 := get_M3u8(modelID, daili)
	m3u8_status := test_m3u8(m3u8, daili)
	if modelID == "false" {
		return nil, live.ErrRoomUrlIncorrect
	}
	if (modelID == "OffLine") || (m3u8 == "false") {
		info = &live.Info{
			Live:     l,
			RoomName: modelID,
			HostName: modelName,
			Status:   m3u8_status,
		}
		return info, nil
	}
	if m3u8 != "false" {
		info = &live.Info{
			Live:     l,
			RoomName: modelID,
			HostName: modelName,
			Status:   m3u8_status,
		}
		return info, nil
	}
	return info, live.ErrInternalError
}

func (l *Live) GetStreamUrls() (us []*url.URL, err error) {
	// modeName := regexp.MustCompile(`stripchat.com\/(\w|-)+`).FindString(l.Url.String())
	modeName := strings.Split(l.Url.String(), "/")
	modelName := modeName[len(modeName)-1]
	daili := GetProxy()
	modelID := get_modelId(modelName, daili)
	m3u8 := get_M3u8(modelID, daili)
	m3u8_status := test_m3u8(m3u8, daili)
	if m3u8_status {
		return utils.GenUrls(m3u8)
	}
	if modelID == "false" || modelID == "OffLine" || m3u8 == "false" || !m3u8_status {
		return nil, err //live.ErrRoomNotExist
	}
	return nil, live.ErrInternalError
}

func (l *Live) GetPlatformCNName() string {
	return cnName
}
