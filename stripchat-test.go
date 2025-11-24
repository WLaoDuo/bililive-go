package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hr3lxphr6j/bililive-go/src/live"
	"github.com/parnurzeal/gorequest"
	"github.com/tidwall/gjson"
)

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
	_, body2, errs2 := OptimizedGet("https://zh.stripchat.com/api/front/models/username/"+modleName+"/knights", daili)
	// _, body2, errs2 := request.Get("https://zh.stripchat.com/api/front/models/username/" + modleName + "/knights").End() //这个url主播离线也能获取id
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

// 全局客户端管理器
type RequestManager struct {
	clients map[string]*http.Client
	mutex   sync.RWMutex
}

var (
	manager *RequestManager
	once    sync.Once
)

// 获取全局管理器实例（单例模式）
func getManager() *RequestManager {
	once.Do(func() {
		manager = &RequestManager{
			clients: make(map[string]*http.Client),
		}
	})
	return manager
}

// 创建优化的HTTP客户端
func (hm *RequestManager) getHTTPManager(proxyURL string) *http.Client {
	// 创建自定义Transport，优化连接池参数
	transport := &http.Transport{
		// 连接池配置
		MaxIdleConns:        600,              // 全局最大空闲连接
		MaxIdleConnsPerHost: 200,              // 每个host的最大空闲连接数
		MaxConnsPerHost:     0,                // 单域名最大连接，0不限制
		IdleConnTimeout:     30 * time.Second, // 空闲连接超时时间

		// 连接超时配置
		DialContext: (&net.Dialer{
			Timeout:   20 * time.Second, // 连接超时
			KeepAlive: 30 * time.Second, // Keep-Alive周期
		}).DialContext,

		// 其他优化配置
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,

		// TLS配置
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // 忽略tls错误
		},

		// 禁用HTTP/2（可选，某些情况下HTTP/1.1性能更好）
		// ForceAttemptHTTP2: false,
	}

	// 如果有代理配置
	if proxyURL != "" {
		if proxyURLParsed, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxyURLParsed)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second, // 整体请求超时
		// 不自动跟随重定向，根据需要调整
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}
}

// 获取或创建HTTP客户端（按代理分组复用）
func (hm *RequestManager) getClient(proxyURL string) *http.Client {
	// 使用代理URL作为key，没有代理则使用"default"
	key := proxyURL
	if key == "" {
		key = "default"
	}

	// 先尝试读取
	hm.mutex.RLock()
	client, exists := hm.clients[key]
	hm.mutex.RUnlock()

	if exists {
		return client
	}

	// 需要创建新客户端，加写锁
	hm.mutex.Lock()
	defer hm.mutex.Unlock()

	// 双重检查锁定
	if client, exists := hm.clients[key]; exists {
		return client
	}

	// 创建新客户端
	client = hm.getHTTPManager(proxyURL)
	hm.clients[key] = client

	return client
}

// 主要的请求函数 - 高性能实现
func OptimizedGet(urlinput, daili string) (*http.Response, string, []error) {
	var errs []error

	// 获取复用的HTTP客户端
	client := getManager().getClient(daili)

	// 创建请求
	req, err := http.NewRequest("GET", urlinput, nil)
	if err != nil {
		return nil, "", []error{fmt.Errorf("创建请求失败: %w", err)}
	}

	// 设置请求头（模拟浏览器）
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
	req.Header.Set("Accept-Encoding", "identity") // 不接受压缩
	// req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0")
	req.Header.Set("Connection", "keep-alive")

	// 执行请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", []error{fmt.Errorf("请求执行失败: %w", err)}
	}

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		return nil, "", []error{fmt.Errorf("读取响应体失败: %w", err)}
	}

	// 重要：关闭原响应体，但我们需要返回响应对象
	resp.Body.Close()

	// 创建新的响应体，以便调用者可以正常使用Response对象
	resp.Body = io.NopCloser(strings.NewReader(string(body)))

	return resp, string(body), errs
}

// return client.Get(urlinput).
// 	Set("Accept", "*/*").
// 	Set("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2").
// 	// Set("Accept-Encoding", "gzip, deflate"). // 压缩 无法自动解压，出现乱码
// 	Set("Accept-Encoding", "identity"). // 不接受压缩
// 	Set("Origin", "https://zh.stripchat.com").
// 	Set("Referer", "https://zh.stripchat.com/").
// 	Set("Priority", "u=4").
// 	Set("Sec-Fetch-Dest", "empty").
// 	Set("Sec-Fetch-Mode", "cors").
// 	Set("Sec-Fetch-Site", "cross-site").
// 	Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0").
// 	Set("Connection", "keep-alive").
// 	End()

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

func get_M3u8(modelId string, daili string) (string, error) {
	if modelId == "" { // || modelId == "false" || modelId == "OffLine" || modelId == "url.Error" {
		return "", ErrNullID
	}
	// urlinput := "https://edge-hls.doppiocdn.net/hls/" + modelId + "/master/" + modelId + "_auto.m3u8?playlistType=standard" //EOF错误
	// urlinput := "https://edge-hls.doppiocdn.com/hls/" + modelId + "/master/" + modelId + "_auto.m3u8?playlistType=standard" //EOF错误
	// urlinput := "https://edge-hls.doppiocdn.org/hls/" + modelId + "/master/" + modelId + "_auto.m3u8?playlistType=standard" //ok
	urlinput := "https://edge-hls.doppiocdn.com/hls/" + modelId + "/master/" + modelId + "_auto.m3u8?psch=v1&pkey=Thoohie4ieRaGaeb&playlistType=standard" //明文
	// https://edge-hls.doppiocdn.net/hls/107278959/master/107278959_auto.m3u8?psch=v1&pkey=Zokee2OhPh9kugh4&playlistType=standard 可解密

	resp, body, errs := OptimizedGet(urlinput, daili)
	if errs != nil {
		fmt.Println("错误的结果", resp, body)
		fmt.Println("get_m3u8错误 ", errs)
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
		fmt.Println("getM3u8结果", body)
		pkeyRe := regexp.MustCompile(`EXT-X-MOUFLON:PSCH:([\w]+):([\w]+)`)
		psch := pkeyRe.FindStringSubmatch(body)[1]
		pkey := pkeyRe.FindStringSubmatch(body)[2]
		fmt.Println(psch, pkey)
		data, err_findm3u8 := regexM3U8(body, 1)
		if err_findm3u8 != nil {
			return "", err_findm3u8
		}
		// data = data + "&psch=" + psch + "&pkey=" + pkey
		// fmt.Println("getM3u8结果=", data)
		return data, nil
	} else {
		return "", ErrFalse
	}
}

func regexM3U8(data string, quality int) (string, error) { //l.Options.Quality
	if quality != 0 && quality != 1 && quality != 2 {
		quality = 0
	}
	nameRe := regexp.MustCompile(`NAME="([\w]+)"`)
	resolutionRe := regexp.MustCompile(`RESOLUTION=([\w]+)`)
	urlRe := regexp.MustCompile(`(https?:\/\/[^\s]+?\.m3u8(?:\?[^\s]+)?)`)

	/*
		data = `
		#EXTM3U
		#EXT-X-VERSION:6
		#EXT-X-MOUFLON:PSCH:v1:Zokee2OhPh9kugh4
		#EXT-X-STREAM-INF:BANDWIDTH=5310976,CODECS="avc1.4d0028,mp4a.40.2",RESOLUTION=1920x1080,FRAME-RATE=30.000,CLOSED-CAPTIONS=NONE,NAME="1080p"
		https://b-hls-23.doppiocdn.live/hls/82030055/82030055_1080p.m3u8?playlistType=standard
		#EXT-X-STREAM-INF:BANDWIDTH=2598604,CODECS="avc1.4d001f,mp4a.40.2",RESOLUTION=1280x720,FRAME-RATE=30.000,CLOSED-CAPTIONS=NONE,NAME="720p"
		https://b-hls-23.doppiocdn.live/hls/82030055/82030055_720p.m3u8?playlistType=standard
		#EXT-X-STREAM-INF:BANDWIDTH=1469952,CODECS="avc1.4d001f,mp4a.40.2",RESOLUTION=854x480,FRAME-RATE=30.000,CLOSED-CAPTIONS=NONE,NAME="480p"
		https://b-hls-23.doppiocdn.live/hls/82030055/82030055_480p.m3u8?playlistType=standard
		#EXT-X-STREAM-INF:BANDWIDTH=719769,CODECS="avc1.4d0015,mp4a.40.2",RESOLUTION=426x240,FRAME-RATE=30.000,CLOSED-CAPTIONS=NONE,NAME="240p"
		https://b-hls-23.doppiocdn.live/hls/82030055/82030055_240p.m3u8?playlistType=standard
		#EXT-X-STREAM-INF:BANDWIDTH=349184,CODECS="avc1.4d400c,mp4a.40.2",RESOLUTION=284x160,FRAME-RATE=30.000,CLOSED-CAPTIONS=NONE,NAME="160p"
		https://b-hls-23.doppiocdn.live/hls/82030055/82030055_160p.m3u8?playlistType=standard
		`
	*/
	nameMatches := nameRe.FindAllStringSubmatch(data, -1)
	urlMatches := urlRe.FindAllStringSubmatch(data, -1)
	resolutionMatches := resolutionRe.FindAllStringSubmatch(data, -1)

	// 检查匹配结果
	if len(nameMatches) == 0 || len(urlMatches) == 0 {
		return "", errors.New(data + "m3u8正则未匹配")
	}
	if len(urlMatches) > 1 {
		result := make(map[string]string) //字典
		for i := 0; i < len(resolutionMatches); i++ {
			if len(resolutionMatches[i]) > 1 && len(urlMatches[i]) > 1 {
				name := resolutionMatches[i][1]
				url := urlMatches[i][1]
				result[name] = url
			}
		}
		// fmt.Println("多个url=\n", result)

		if quality == 0 { //储存优先480p
			for k, v := range result {
				if strings.Contains(k, "480") {
					return v, nil
				}
			}
			return urlMatches[len(urlMatches)-2][1], nil //倒数第二
		}
		if quality == 1 { //720p优先
			for k, v := range result {
				if strings.Contains(k, "720") {
					return v, nil
				}
			}
			return urlMatches[1][1], nil //失败回退 第二清晰度
		}
		if quality == 2 { //清晰度最高，第一清晰度urlMatches[0][1]
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
		request.Client.Transport = &http.Transport{
			// ForceAttemptHTTP2: false, // 强制使用 HTTP/1.1
			// TLSClientConfig: &tls.Config{
			// 	MinVersion:         tls.VersionTLS12, // 强制使用 TLS 1.2
			// 	InsecureSkipVerify: true,             // 仅用于测试，生产环境不要使用
			// },
			DisableKeepAlives: true, // 禁用 Keep-Alive
		}
		resp, body, errs := request.Get(urlinput).End()
		if errs != nil {
			fmt.Println("test_m3u8错误", errs)
			for _, err := range errs {
				if _, ok := err.(*url.Error); ok {
					return false, live.ErrInternalError
				}
			}
			return false, ErrFalse
		}
		// fmt.Println(resp.StatusCode)
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
func GetInfo(l *Live, modelName string, daili string) (info *live.Info, err error) {

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
			Live:         nil,
			RoomName:     l.model_ID,
			HostName:     modelName,
			Status:       true,
			CustomLiveId: m3u8, //l.GetLiveId()可获取持久化数据
		}
		return info, nil
	}
	if errors.Is(err_testm3u8, ErrOffline) || errors.Is(err_getm3u8, ErrOffline) {
		info = &live.Info{
			Live:     nil,
			RoomName: "OffLine",
			HostName: modelName,
			Status:   m3u8_status, //false,
		}
		return info, nil
	}
	if errors.Is(err_testm3u8, live.ErrInternalError) || errors.Is(err_getm3u8, live.ErrInternalError) {
		return nil, live.ErrInternalError
	}
	return nil, err_testm3u8
}

type Live struct {
	// internal.BaseLive
	model_ID string
	m3u8Url  string
}

type Decrypter struct {
	stripchatKey string
	hashCache    map[string][]byte
	session      *http.Client
}

func NewDecrypter(stripchatKey string) *Decrypter {
	return &Decrypter{
		stripchatKey: stripchatKey,
		hashCache:    make(map[string][]byte),
	}
}

// ProcessM3U8ContentV2 处理M3U8内容，解密其中的加密文件名
func (d *Decrypter) ProcessM3U8ContentV2(m3u8Content string) string {
	lines := strings.Split(strings.TrimSpace(m3u8Content), "\n")
	for i := 0; i < len(lines)-1; i++ {
		line := lines[i]
		if strings.HasPrefix(line, "#EXT-X-MOUFLON:FILE:") && strings.Contains(lines[i+1], "media.mp4") {
			// 提取加密数据
			parts := strings.SplitN(line, ":", 3)
			if len(parts) < 3 {
				continue
			}
			encryptedData := strings.TrimSpace(parts[2])

			// 尝试使用主密钥解密
			decryptedData, err := d.Decrypt(encryptedData, d.stripchatKey)
			if err != nil {
				// 主密钥失败，尝试备用密钥
				decryptedData, err = d.Decrypt(encryptedData, "Zokee2OhPh9kugh4")
				if err != nil {
					fmt.Printf("解密失败: %v\n", err)
					decryptedData = ""
				}
			}

			// 替换media.mp4为解密后的文件名
			lines[i+1] = strings.ReplaceAll(lines[i+1], "media.mp4", decryptedData)
		}
	}
	return strings.Join(lines, "\n")
}

// Decrypt Base64编码的异或解密算法
func (d *Decrypter) Decrypt(encryptedB64, key string) (string, error) {
	// 修复Base64填充 - 确保与Python版本完全一致
	// Python 版本: padding = len(encrypted_b64) % 4
	padding := len(encryptedB64) % 4
	if padding > 0 {
		// Python 版本: encrypted_b64 += '=' * (4 - padding)
		encryptedB64 += strings.Repeat("=", 4-padding)
	}

	// 计算哈希 - 确保与Python版本一致
	hashBytes, err := d.computeHashBytes(key)
	if err != nil {
		return "", fmt.Errorf("计算哈希失败: %w", err)
	}

	// Base64解码 - 使用与Python相同的解码方式
	// Python 版本: base64.b64decode(encrypted_b64)
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return "", fmt.Errorf("Base64解码失败: %w", err)
	}

	// 异或解密 - 核心解密算法
	// 使用与Python完全相同的逻辑
	// Python 版本: decrypted_bytes = bytearray()
	decryptedBytes := make([]byte, 0, len(encryptedData))

	for i, cipherByte := range encryptedData {
		// 循环使用哈希字节作为密钥
		// Python 版本: key_byte = hash_bytes[i % len(hash_bytes)]
		keyByte := hashBytes[i%len(hashBytes)]

		// 执行异或操作
		// Python 版本: decrypted_bytes.append(cipher_byte ^ key_byte)
		decryptedBytes = append(decryptedBytes, cipherByte^keyByte)
	}

	// 将解密后的字节转换为UTF-8字符串
	// Python 版本: decrypted_bytes.decode('utf-8')
	// 添加UTF-8有效性检查
	if !utf8.Valid(decryptedBytes) {
		// 打印解密后的字节用于调试
		// fmt.Printf("解密后的字节: %v\n", decryptedBytes)
		return "", fmt.Errorf("解密结果不是有效的UTF-8编码")
	}

	return string(decryptedBytes), nil
}

// computeHashBytes 计算SHA-256哈希值
func (d *Decrypter) computeHashBytes(key string) ([]byte, error) {
	// 检查缓存
	if cached, exists := d.hashCache[key]; exists {
		return cached, nil
	}

	// 计算新哈希 - 确保与Python版本一致
	// Python 版本: hashlib.sha256(key.encode('utf-8')).digest()
	hasher := sha256.New()
	hasher.Write([]byte(key)) // 默认使用UTF-8编码
	hash := hasher.Sum(nil)

	// 缓存结果
	d.hashCache[key] = hash
	return hash, nil
}
func main() {
	var name = flag.String("u", "Sakura_Anne", "主播名字")
	var daili = flag.String("p", "http://127.0.0.1:7890", "代理")
	flag.Parse()
	// m3u8 := get_M3u8(get_modelId("Sakura_Anne"))
	// m3u8 := get_M3u8(get_modelId("Ko_Alanna"))
	// m3u8 := get_M3u8(get_modelId("NEW-girl520"))
	// m3u8 := get_M3u8(get_modelId("Lucky-uu"))
	// m3u8 := get_M3u8(get_modelId("Hahaha_ha2"))
	// m3u8 := get_M3u8(get_modelId("8-Monica"))
	fmt.Println("input=", *name)
	modelID, err_getid := get_modelId(*name, *daili)
	fmt.Println(*name, modelID)
	m3u81, err_getm3u8 := get_M3u8(modelID, *daili)
	fmt.Println(m3u81)
	result, err_test := test_m3u8(m3u81, *daili)
	if result == true {
		_, m3u8_encrypted, err_getm3u82 := OptimizedGet(m3u81, *daili)
		if err_getm3u82 != nil {
			fmt.Println(err_getm3u82)
		}
		fmt.Println("被加密的", m3u81, "内容\n", m3u8_encrypted)

		decrypter := NewDecrypter("Quean4cai9boJa5a")
		m3u8_decode := decrypter.ProcessM3U8ContentV2(m3u8_encrypted)
		fmt.Println("解密结果:", m3u8_decode)
	}

	test := Live{model_ID: modelID, m3u8Url: m3u81}
	fmt.Println("\ngetinfo调用的getm3u8结果:")
	fmt.Println(GetInfo(&test, *name, *daili))

	if modelID != "" {
		if err_getm3u8 == nil && err_test == nil && err_getid == nil {
			fmt.Println("m3u8=", m3u81, "测试结果：", result)
			fmt.Println("ffmpeg.exe -http_proxy ", *daili, " -copyts -progress - -y -i ", "'"+m3u81+"'", " -c copy -rtbufsize ", "./ceshi_copyts.mkv")
		}
	}
	if err_getid != nil || err_getm3u8 != nil || err_test != nil {
		fmt.Println("err_getid=", err_getid, "\nerr_getm3u8=", err_getm3u8, "\nerr_test=", err_test)
	}
}
