package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strconv"

	"github.com/parnurzeal/gorequest"
	"github.com/tidwall/gjson"
)

func get_modelId(modleName string, daili string) string {

	fmt.Println("主播名字：", modleName)
	request := gorequest.New()
	if daili != "" {
		request = request.Proxy(daili)
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
	if errs != nil {
		fmt.Println("get_modeId出错详情:")
		for _, err := range errs {
			if err1, ok := err.(*url.Error); ok {
				// urlErr 是 *url.Error 类型的错误
				fmt.Println("请求出错,可能网络故障", errs)
				// fmt.Println("*url.Error 类型的错误")
				if err2, ok := err1.Err.(*net.OpError); ok {
					// netErr 是 *net.OpError 类型的错误
					// 可以进一步判断 netErr.Err 的类型
					fmt.Println("*net.OpError 类型的错误", err.Error(), err2.Op)
				}
				return "url.Error"
			} else {
				fmt.Println(reflect.TypeOf(err), "错误详情:", err)
			}
		}
		return "false"
	} else {
		// 解析 JSON 响应
		if len(gjson.Get(body, "messages").String()) > 2 {
			modelId := gjson.Get(body, "messages.0.modelId").String()
			return modelId
		} else if len(gjson.Get(body, "messages").String()) == 2 {
			fmt.Println("offline")
			return "OffLine"
		} else if len(gjson.Get(body, "messages").String()) == 0 {
			fmt.Println("error name")
			return "false"
		}
		fmt.Println("len messages=", len(gjson.Get(body, "messages").String()), "\nmessages:", gjson.Get(body, "messages").String())
		return "false"
	}
}

func get_M3u8(modelId string, daili string) (string, string) {
	// fmt.Println(modelId)
	// url := "https://edge-hls.doppiocdn.com/hls/" + modelId + "/master/" + modelId + "_auto.m3u8?playlistType=lowLatency"
	// url := "https://edge-hls.doppiocdn.com/hls/" + modelId + "/master/" + modelId + "_auto.m3u8" //可选分辨率视频，比原视频糊
	// url := "https://edge-hls.doppiocdn.com/hls/" + modelId + "/master/" + modelId + ".m3u8?playlistType=lowLatency"
	url := "https://edge-hls.doppiocdn.com/hls/" + modelId + "/master/" + modelId + ".m3u8" //源视频，最高分辨率
	request := gorequest.New()
	if daili != "" {
		request = request.Proxy(daili) //代理
	}
	resp, body, errs := request.Get(url).End()

	if modelId == "false" || modelId == "OffLine" || modelId == "url.Error" || resp.StatusCode != 200 || len(errs) > 0 {
		return "false", "false"
	} else {
		fmt.Println((body))
		re0 := regexp.MustCompile(`BANDWIDTH=([\d]+)`)
		BANDWIDTH := re0.FindStringSubmatch(body)
		bandwidthValue := "10M"
		bandwidthValue1 := 0
		if len(BANDWIDTH) == 2 {
			bandwidthValue1, _ = strconv.Atoi(BANDWIDTH[1]) // 提取括号内的内容
			bandwidthValue = strconv.Itoa(bandwidthValue1 * 5)
		}
		fmt.Println("码率:", bandwidthValue)
		// re := regexp.MustCompile(`(https:\/\/[\w\-\.]+\/hls\/[\d]+\/[\d\_p]+\.m3u8\?playlistType=lowLatency)`)
		re := regexp.MustCompile(`(https:\/\/[\w\-\.]+\/hls\/[\d]+\/[\d\_p]+\.m3u8)`)
		url := re.FindString(body)

		return url, bandwidthValue
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
	m3u8, bandwidth := get_M3u8(get_modelId(*name, *daili), *daili)
	fmt.Println("m3u8=", m3u8, "测试结果：", test_m3u8(m3u8, *daili))
	fmt.Println("ffmpeg.exe -http_proxy ", *daili, " -copyts -progress - -y -i ", m3u8, " -c copy -rtbufsize ", bandwidth, "./ceshi_copyts.mkv")

}
