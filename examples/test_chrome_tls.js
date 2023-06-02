// thanks for https://github.com/lwthiker/curl-impersonate
const { Curl, CurlHttpVersion, CurlSslVersion } = require('../dist')
// const { Curl, CurlHttpVersion, CurlSslVersion } = require('@ycq0125/node-libcurl')
console.log(Curl.getVersionInfoString())

async function main() {
  const headers = [
    'sec-ch-ua: "Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24',
    'sec-ch-ua-mobile: ?0',
    'sec-ch-ua-platform: "macOS',
    'upgrade-insecure-requests: 1',
    'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
    'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'sec-fetch-site: none',
    'sec-fetch-mode: navigate',
    'sec-fetch-user: ?1',
    'sec-fetch-dest: document',
    'accept-encoding: gzip, deflate, br',
    'accept-language: zh-CN,zh;q=0.9',
  ]

  const curl = new Curl()

  curl.setOpt(Curl.option.URL, 'https://tls.peet.ws/api/all')
  curl.setOpt('SSL_VERIFYHOST', 0)
  curl.setOpt('SSL_VERIFYPEER', 0)
  // curl.setOpt(Curl.option.URL, 'https://tools.scrapfly.io/api/info/tls')
  curl.setOpt(Curl.option.FOLLOWLOCATION, 1)
  curl.setOpt(Curl.option.VERBOSE, 1)
  curl.setOpt(Curl.option.HTTPHEADER, headers)
  curl.setOpt(Curl.option.HTTP_VERSION, CurlHttpVersion.V2_0)
  curl.setOpt(Curl.option.ACCEPT_ENCODING, 'gzip, deflate, br')
  curl.setOpt(
    Curl.option.SSL_CIPHER_LIST,
    'TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-ECDSA-CHACHA20-POLY1305,ECDHE-RSA-CHACHA20-POLY1305,ECDHE-RSA-AES128-SHA,ECDHE-RSA-AES256-SHA,AES128-GCM-SHA256,AES256-GCM-SHA384,AES128-SHA,AES256-SHA',
  )
  curl.setOpt(Curl.option.SSLVERSION, CurlSslVersion.TlsV1_2)
  curl.setOpt(Curl.option.SSL_ENABLE_NPN, 0)
  curl.setOpt(Curl.option.SSL_ENABLE_ALPS, 1)
  curl.setOpt(Curl.option.SSL_COMPRESSION, 'brotli')
  curl.setOpt(Curl.option.HTTP2_NO_SERVER_PUSH, 1)

  curl.on('end', function (status, data, headers) {
    console.log(status)
    console.log(data)
    console.log(headers)
    this.close()
  })

  curl.perform()
}

main()
