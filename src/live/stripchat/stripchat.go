package stripchat

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

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
	// request := gorequest.New()
	// if daili != "" {
	// 	request = request.Proxy(daili) //代理
	// }

	// // 添加头部信息
	// request.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	// request.Set("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
	// request.Set("Accept-Encoding", "gzip, deflate")
	// request.Set("Upgrade-Insecure-Requests", "1")
	// request.Set("Sec-Fetch-Dest", "document")
	// request.Set("Sec-Fetch-Mode", "navigate")
	// request.Set("Sec-Fetch-Site", "none")
	// request.Set("Sec-Fetch-User", "?1")
	// request.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0")
	// // request.Set("If-Modified-Since", "Mon, 29 Jul 2024 08:41:12 GMT")
	// request.Set("Te", "trailers")
	// request.Set("Connection", "close")

	//优先此api
	// _, body2, errs2 := request.Get("https://zh.stripchat.com/api/front/models/username/" + modleName + "/knights").End() //这个url主播离线也能获取id
	_, body2, errs2 := OptimizedGet("https://zh.stripchat.com/api/front/models/username/"+modleName+"/knights", daili)
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
	// _, body, errs := request.Get("https://zh.stripchat.com/api/front/v2/models/username/" + modleName + "/chat").End()
	_, body, errs := OptimizedGet("https://zh.stripchat.com/api/front/v2/models/username/"+modleName+"/chat", daili)
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

// 连接池管理器 - 只管理http.Transport，不共享gorequest实例
type TransportManager struct {
	transports map[string]*http.Transport
	mutex      sync.RWMutex
}

var (
	transportManager *TransportManager
	once             sync.Once
)

// 获取全局Transport管理器实例（单例模式）
func getTransportManager() *TransportManager {
	once.Do(func() {
		transportManager = &TransportManager{
			transports: make(map[string]*http.Transport),
		}
	})
	return transportManager
}

// 创建优化的 Transport 实例
func createOptimizedTransport(daili string) *http.Transport {
	transport := &http.Transport{
		MaxIdleConns:        200,              // 全局最大空闲连接
		MaxIdleConnsPerHost: 100,              // 单域名最大空闲连接
		MaxConnsPerHost:     0,                // 单域名最大连接，0不限制
		IdleConnTimeout:     90 * time.Second, // 空闲连接超时

		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},

		DisableKeepAlives:     false,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	// 设置代理
	if daili != "" {
		if proxyUrl, err := url.Parse(daili); err == nil {
			transport.Proxy = http.ProxyURL(proxyUrl)
		}
	}

	return transport
}

// 获取Transport实例（自动初始化和复用）
func (tm *TransportManager) getTransport(daili string) *http.Transport {
	tm.mutex.RLock()
	transport, exists := tm.transports[daili]
	tm.mutex.RUnlock()

	if exists {
		return transport
	}

	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// 双重检查锁定
	if transport, exists := tm.transports[daili]; exists {
		return transport
	}

	transport = createOptimizedTransport(daili)
	tm.transports[daili] = transport
	return transport
}

// 为每个请求创建新的gorequest实例，但复用Transport
func createRequestWithSharedTransport(daili string) *gorequest.SuperAgent {
	request := gorequest.New()

	// 获取共享的Transport
	transport := getTransportManager().getTransport(daili)
	request.Transport = transport

	// 设置代理（如果gorequest实例需要单独处理代理逻辑）
	if daili != "" {
		request = request.Proxy(daili)
	}

	request.Timeout(60 * time.Second)

	return request
}

// 修复后的主要请求函数 - 每次创建新的gorequest实例
func OptimizedGet(urlinput, daili string) (*http.Response, string, []error) {
	// 关键修复：为每个请求创建新的SuperAgent实例
	// 这样避免了多个goroutine共享同一个SuperAgent实例导致的并发问题
	client := createRequestWithSharedTransport(daili)

	return client.Get(urlinput).
		Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8").
		Set("Accept-Language", "en-US,en;q=0.5").
		Set("Accept-Encoding", "identity"). // 不接受压缩
		Set("Upgrade-Insecure-Requests", "1").
		Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0 Herring/91.1.1890.10").
		Set("Connection", "keep-alive").
		End()
}

// POST 请求封装
func OptimizedPost(urlinput, daili string, data interface{}) (*http.Response, string, []error) {
	client := createRequestWithSharedTransport(daili)

	return client.Post(urlinput).
		Send(data).
		Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8").
		Set("Accept-Language", "en-US,en;q=0.5").
		Set("Accept-Encoding", "identity"). // 不接受压缩
		Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0 Herring/91.1.1890.10").
		Set("Connection", "keep-alive").
		End()
}

// 带自定义头部的请求函数
func OptimizedGetWithHeaders(urlinput, daili string, headers map[string]string) (*http.Response, string, []error) {
	client := createRequestWithSharedTransport(daili)

	req := client.Get(urlinput).
		Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8").
		Set("Accept-Language", "en-US,en;q=0.5").
		Set("Accept-Encoding", "identity"). // 不接受压缩
		Set("Upgrade-Insecure-Requests", "1").
		Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0 Herring/91.1.1890.10").
		Set("Connection", "keep-alive")

	// 添加自定义头部
	for key, value := range headers {
		req = req.Set(key, value)
	}

	return req.End()
}

// 带重试机制的请求
func OptimizedGetWithRetry(urlinput, daili string, maxRetries int) (*http.Response, string, []error) {
	var resp *http.Response
	var body string
	var errs []error

	for i := 0; i < maxRetries; i++ {
		resp, body, errs = OptimizedGet(urlinput, daili)

		// 检查是否成功
		if len(errs) == 0 && resp != nil && resp.StatusCode < 500 {
			return resp, body, errs
		}

		// 指数退避重试
		if i < maxRetries-1 {
			time.Sleep(time.Duration(i+1) * time.Second)
		}
	}

	return resp, body, errs
}

// 并发控制版本
type ConcurrentRequester struct {
	semaphore chan struct{}
}

func NewConcurrentRequester(maxConcurrency int) *ConcurrentRequester {
	return &ConcurrentRequester{
		semaphore: make(chan struct{}, maxConcurrency),
	}
}

func (cr *ConcurrentRequester) Get(urlinput, daili string) (*http.Response, string, []error) {
	cr.semaphore <- struct{}{}
	defer func() { <-cr.semaphore }()

	return OptimizedGet(urlinput, daili)
}

// 清理函数 - 清理Transport池
func CleanupTransports() {
	if transportManager != nil {
		transportManager.mutex.Lock()
		defer transportManager.mutex.Unlock()

		// 关闭所有Transport的空闲连接
		for _, transport := range transportManager.transports {
			transport.CloseIdleConnections()
		}

		// 重新初始化
		transportManager.transports = make(map[string]*http.Transport)
	}
}
func get_M3u8(modelId string, daili string, flag int) (string, error) {
	if modelId == "" { // || modelId == "false" || modelId == "OffLine" || modelId == "url.Error" {
		return "", ErrNullID
	}
	// url := "https://edge-hls.doppiocdn.com/hls/" + modelId + "/master/" + modelId + "_auto.m3u8?playlistType=lowLatency"
	urlinput := "https://edge-hls.doppiocdn.net/hls/" + modelId + "/master/" + modelId + "_auto.m3u8?psch=v1&pkey=Thoohie4ieRaGaeb&playlistType=standard" //明文

	resp, body, errs := OptimizedGet(urlinput, daili)
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
		// re := regexp.MustCompile(`(https?:\/\/[^\s]+?\.m3u8(?:\?[^\s]+)?)`) //https://media-hls.doppiocdn.com/b-hls-10/82030055/82030055_720p60.m3u8更新
		// matches := re.FindAllString(body, -1)                               // -1表示匹配所有结果
		// if len(matches) > 1 {
		// 	secondMatch := matches[1]
		// 	return secondMatch, nil
		// }
		// if len(matches) == 1 {
		// 	return matches[0], nil
		// } else {
		// 	return "", errors.New(body + "m3u8正则未匹配")
		// }
		m3u8, err_findm3u8 := regexM3U8(body, flag)
		if err_findm3u8 != nil {
			return "", err_findm3u8
		}
		return m3u8, nil
	} else {
		return "", ErrFalse
	}
}

func regexM3U8(data string, flag int) (string, error) { //l.Options.Quality
	if flag != 0 && flag != 1 && flag != 2 {
		flag = 0
	}
	nameRe := regexp.MustCompile(`NAME="([\w]+)"`)
	urlRe := regexp.MustCompile(`(https?:\/\/[^\s]+?\.m3u8(?:\?[^\s]+)?)`)

	nameMatches := nameRe.FindAllStringSubmatch(data, -1)
	urlMatches := urlRe.FindAllStringSubmatch(data, -1)

	// 检查匹配结果
	if len(nameMatches) == 0 || len(urlMatches) == 0 {
		return "", errors.New(data + "m3u8正则未匹配")
	}
	if len(urlMatches) > 1 {
		result := make(map[string]string) //字典
		for i := 0; i < len(nameMatches); i++ {
			if len(nameMatches[i]) > 1 && len(urlMatches[i]) > 1 {
				name := nameMatches[i][1]
				url := urlMatches[i][1]
				result[name] = url
			}
		}
		// fmt.Println("多个url=\n", result)

		if flag == 0 { //储存优先480p
			for k, v := range result {
				if strings.Contains(k, "480p") {
					return v, nil
				}
			}
			return urlMatches[len(urlMatches)-2][1], nil //失败回退 倒数第二清晰度
		}
		if flag == 1 { //720p优先
			for k, v := range result {
				if strings.Contains(k, "720p") {
					return v, nil
				}
			}
			return urlMatches[1][1], nil //失败回退 第二清晰度
		}
		if flag == 2 { //清晰度最高，第一清晰度urlMatches[0][1]
			return urlMatches[0][1], nil
		}
	}
	if len(urlMatches) == 1 { //仅有一个url
		return urlMatches[0][1], nil
	}
	return "", errors.New(data + "m3u8正则未匹配")
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

	m3u8, err_getm3u8 := get_M3u8(l.model_ID, daili, l.Options.Quality)

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
		m3u8, err := get_M3u8(l.model_ID, daili, l.Options.Quality)
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
