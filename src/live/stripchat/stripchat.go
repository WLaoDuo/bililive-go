package stripchat

import (
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/hr3lxphr6j/bililive-go/src/cmd/bililive/readconfig"
	"github.com/hr3lxphr6j/bililive-go/src/live"
	"github.com/hr3lxphr6j/bililive-go/src/live/internal"
	"github.com/hr3lxphr6j/bililive-go/src/pkg/utils"
	"github.com/parnurzeal/gorequest"
	"github.com/tidwall/gjson"
)

func init() {
	live.Register(domain, new(builder))
}

type builder struct{}

func (b *builder) Build(url *url.URL, opt ...live.Option) (live.Live, error) {
	return &Live{
		BaseLive: internal.NewBaseLive(url, opt...),
	}, nil
}

var (
	ErrFalse                     = errors.New("false")
	ErrModelName                 = errors.New("err model name")
	Err_GetInfo_Unexpected       = errors.New("GetInfo未知错误")
	Err_GetStreamUrls_Unexpected = errors.New("GetStreamUrls未知错误")
	Err_TestUrl_Unexpected       = errors.New("testUrl未知错误")
	ErrOffline                   = errors.New("OffLine")
	ErrNullUrl                   = errors.New("null url")
	ErrNullID                    = errors.New("null ID")
)

func get_modelId(modleName string, daili string) (string, error) {
	if modleName == "" {
		return "", ErrModelName
	}
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

	//优先此api
	_, body2, errs2 := request.Get("https://zh.stripchat.com/api/front/models/username/" + modleName + "/knights").End() //这个url主播离线也能获取id
	if errs2 != nil {
		for _, err := range errs2 {
			if urlErr, ok := err.(*url.Error); ok {
				// 处理网络错误
				fmt.Println("URL2请求失败(网络错误):", urlErr)
				return "", live.ErrInternalError
			} else {
				fmt.Println(reflect.TypeOf(err), "错误详情:", err)
				return "", err
			}
		}
		return "", ErrFalse
	}
	if body2 != "" && gjson.Get(body2, "modelId").String() != "" {
		return gjson.Get(body2, "modelId").String(), nil
	}

	//此api需要等主播上线才可用，适用性差
	_, body, errs := request.Get("https://zh.stripchat.com/api/front/v2/models/username/" + modleName + "/chat").End()
	if errs != nil {
		for _, err := range errs {
			if _, ok := err.(*url.Error); ok {
				// urlErr 是 *url.Error 类型的错误
				// fmt.Println("*url.Error 类型的错误")
				// if err2, ok := err1.Err.(*net.OpError); ok {
				// 	// netErr 是 *net.OpError 类型的错误
				// 	// 可以进一步判断 netErr.Err 的类型
				// 	fmt.Println("*net.OpError 类型的错误", err.Error(), err2.Op)
				// }
				return "", live.ErrInternalError
			} else {
				fmt.Println(reflect.TypeOf(err), "错误详情:", err)
				return "", err
			}
		}
		return "", ErrFalse
	} else {
		if len(gjson.Get(body, "messages").String()) > 2 {
			modelId := gjson.Get(body, "messages.0.modelId").String()
			return modelId, nil
		} else if len(gjson.Get(body, "messages").String()) == 2 {
			return "", ErrOffline
		} else if len(gjson.Get(body, "messages").String()) == 0 {
			return "", ErrModelName
		}
		return "", ErrFalse
	}
}

func get_M3u8(modelId string, daili string) (string, error) {
	if modelId == "" { // || modelId == "false" || modelId == "OffLine" || modelId == "url.Error" {
		return "", ErrNullID
	}
	// url := "https://edge-hls.doppiocdn.com/hls/" + modelId + "/master/" + modelId + "_auto.m3u8?playlistType=lowLatency"
	urlinput := "https://edge-hls.doppiocdn.net/hls/" + modelId + "/master/" + modelId + "_auto.m3u8?playlistType=standard"
	// url := "https://edge-hls.doppiocdn.com/hls/" + modelId + "/master/" + modelId + ".m3u8"
	//https://edge-hls.doppiocdn.com/hls/82030055/master/82030055_auto.m3u8
	//https://media-hls.doppiocdn.com/b-hls-20/82030055/82030055.m3u8
	//https://edge-hls.doppiocdn.com/hls/82030055/master/82030055.m3u8
	request := gorequest.New()
	if daili != "" {
		request = request.Proxy(daili) //代理
	}
	request.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	request.Set("Accept-Language", "en-US,en;q=0.5")
	request.Set("Accept-Encoding", "gzip, deflate")
	request.Set("Upgrade-Insecure-Requests", "1")
	request.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0 Herring/91.1.1890.10")
	request.Set("Connection", "close")

	resp, body, errs := request.Get(urlinput).End()
	if errs != nil {
		for _, err := range errs {
			if _, ok := err.(*url.Error); ok {
				return "", live.ErrInternalError
			}
		}
		return "", ErrFalse
	}
	if resp.StatusCode == 404 || resp.StatusCode == 403 {
		return "", ErrOffline
	}
	if resp.StatusCode == 200 {
		// re := regexp.MustCompile(`(https:\/\/[\w\-\.]+\/hls\/[\d]+\/[\d\_p]+\.m3u8\?playlistType=lowLatency)`)
		// re := regexp.MustCompile(`(https:\/\/[\w\-\.]+\/hls\/[\d]+\/[\d\_p]+\.m3u8\?playlistType=standard)`) //等价于\?playlistType=standard
		re := regexp.MustCompile(`(https?:\/\/[^\s]+?\.m3u8(?:\?[^\s]+)?)`) //https://media-hls.doppiocdn.com/b-hls-10/82030055/82030055_720p60.m3u8更新
		matches := re.FindAllString(body, -1)                               // -1表示匹配所有结果
		if len(matches) > 1 {
			secondMatch := matches[1]
			return secondMatch, nil
		}
		if len(matches) == 1 {
			return matches[0], nil
		} else {
			return "", errors.New(body + "m3u8正则未匹配")
		}
	} else {
		return "", ErrFalse
	}
}
func test_m3u8(urlinput string, daili string) (bool, error) {
	if urlinput == "" {
		return false, ErrNullUrl
	} else {
		request := gorequest.New()
		if daili != "" {
			request = request.Proxy(daili) //代理
		}
		resp, body, errs := request.Get(urlinput).End()
		if errs != nil {
			for _, err := range errs {
				if _, ok := err.(*url.Error); ok {
					return false, live.ErrInternalError
				}
			}
			return false, ErrFalse
		}
		if resp.StatusCode == 200 {
			_ = body
			return true, nil
		}
		if resp.StatusCode == 403 || resp.StatusCode == 404 { //403代表开票，普通用户无法查看，只能看大厅表演
			_ = body
			return false, ErrOffline
		}
		if resp.StatusCode != 200 {
			return false, errors.New(strconv.Itoa(resp.StatusCode))
		}
		return false, Err_TestUrl_Unexpected
	}
}

const (
	domain = "zh.stripchat.com"
	cnName = "stripchat"
)

type Live struct {
	internal.BaseLive
	model_ID string
	m3u8Url  string
}

type MultiError struct {
	ErrTestM3U8 error
	ErrGetID    error
	ErrGetM3U8  error
}

func (e MultiError) Error() string {
	var errors []string
	if e.ErrGetID != nil {
		errors = append(errors, "ErrGetID: "+e.ErrGetID.Error())
	}
	if e.ErrGetM3U8 != nil {
		errors = append(errors, "ErrGetM3U8: "+e.ErrGetM3U8.Error())
	}
	if e.ErrTestM3U8 != nil {
		errors = append(errors, "ErrTestM3U8: "+e.ErrTestM3U8.Error())
	}
	return strings.Join(errors, "; ")
}

func (l *Live) GetInfo() (info *live.Info, err error) {
	modeName := strings.Split(l.Url.String(), "/")
	modelName := modeName[len(modeName)-1]
	daili := ""
	config, config_err := readconfig.Get_config()
	if config_err == nil {
		daili = config.Proxy
	}

	// 优先使用缓存的 model_ID
	if l.model_ID == "" {
		modelID, err_getid := get_modelId(modelName, daili)
		if err_getid != nil {
			if errors.Is(err_getid, live.ErrInternalError) {
				return nil, live.ErrInternalError
			}
			return nil, err_getid
		}
		l.model_ID = modelID
	}

	m3u8, err_getm3u8 := get_M3u8(l.model_ID, daili)

	if m3u8 == "" && l.m3u8Url != "" { //m3u8默认优先，l.m3u8Url缓存兜底
		m3u8 = l.m3u8Url
	}
	m3u8_status, err_testm3u8 := test_m3u8(m3u8, daili)

	if m3u8_status { //strings.Contains(m3u8, ".m3u8")
		if l.m3u8Url != m3u8 {
			l.m3u8Url = m3u8 //l.m3u8Url缓存更新机制，m3u8优先级高
		}

		info = &live.Info{
			Live:         l,
			RoomName:     l.model_ID,
			HostName:     modelName,
			Status:       true,
			CustomLiveId: m3u8, //l.GetLiveId()可获取持久化数据
		}
		return info, nil
	}
	if errors.Is(err_testm3u8, ErrOffline) || errors.Is(err_getm3u8, ErrOffline) {
		info = &live.Info{
			Live:     l,
			RoomName: "OffLine",
			HostName: modelName,
			Status:   m3u8_status, //false,
		}
		return info, nil
	}
	if errors.Is(err_testm3u8, live.ErrInternalError) || errors.Is(err_getm3u8, live.ErrInternalError) {
		return nil, live.ErrInternalError
	}
	return nil, MultiError{
		ErrTestM3U8: err_testm3u8,
		ErrGetID:    nil,
		ErrGetM3U8:  err_getm3u8,
	}
}

func (l *Live) GetStreamUrls() (us []*url.URL, err error) {
	// l.Options.Quality
	modeName := strings.Split(l.Url.String(), "/")
	modelName := modeName[len(modeName)-1]
	daili := ""
	config, config_err := readconfig.Get_config()
	if config_err == nil {
		daili = config.Proxy
	}

	if l.model_ID == "" {
		modelID, err_getid := get_modelId(modelName, daili)
		if err_getid != nil {
			return nil, err_getid
		}
		l.model_ID = modelID
	}
	if l.m3u8Url == "" {
		m3u8, err := get_M3u8(l.model_ID, daili)
		if err != nil {
			return nil, err
		}
		l.m3u8Url = m3u8
	}

	m3u8_status, err_testm3u8 := test_m3u8(l.m3u8Url, daili)
	if m3u8_status {
		return utils.GenUrls(l.m3u8Url)
	}

	if !m3u8_status {
		return nil, err_testm3u8
	}

	return nil, Err_GetStreamUrls_Unexpected
}

func (l *Live) GetPlatformCNName() string {
	return cnName
}
