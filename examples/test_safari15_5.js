// thanks for https://github.com/lwthiker/curl-impersonate
const { Curl, CurlSslVersion } = require('../dist')
// const { Curl, CurlSslVersion } = require('@ycq0125/node-libcurl')
console.log(Curl.getVersionInfoString())

async function main() {
  const headers = [
    'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15',
    'accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'accept-encoding: gzip, deflate, br',
    'accept-language: en-GB,en-US;q=0.9,en;q=0.8',
  ]

  const curl = new Curl()

  curl.setOpt(Curl.option.URL, 'https://tls.peet.ws/api/all')
  curl.setOpt('SSL_VERIFYHOST', 0)
  curl.setOpt('SSL_VERIFYPEER', 0)
  // curl.setOpt(Curl.option.URL, 'https://tools.scrapfly.io/api/info/tls')
  curl.setOpt(Curl.option.FOLLOWLOCATION, 1)
  curl.setOpt(Curl.option.VERBOSE, 1)
  curl.setOpt(Curl.option.HTTPHEADER, headers)
  curl.setOpt(Curl.option.ACCEPT_ENCODING, 'gzip, deflate, br')
  curl.setOpt(
    Curl.option.SSL_CIPHER_LIST,
    'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:TLS_RSA_WITH_3DES_EDE_CBC_SHA',
  )
  curl.setOpt(Curl.option.SSL_EC_CURVES, 'X25519:P-256:P-384:P-521')
  curl.setOpt(
    Curl.option.SSL_SIG_HASH_ALGS,
    'ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256,rsa_pkcs1_sha256,ecdsa_secp384r1_sha384,ecdsa_sha1,rsa_pss_rsae_sha384,rsa_pss_rsae_sha384,rsa_pkcs1_sha384,rsa_pss_rsae_sha512,rsa_pkcs1_sha512,rsa_pkcs1_sha1',
  )
  curl.setOpt(Curl.option.SSLVERSION, CurlSslVersion.TlsV1_0)
  curl.setOpt(Curl.option.SSL_ENABLE_NPN, 0)
  curl.setOpt(Curl.option.SSL_ENABLE_ALPS, 0)
  curl.setOpt(Curl.option.SSL_ENABLE_TICKET, 0)
  curl.setOpt(Curl.option.SSL_COMPRESSION, 'zlib')
  curl.setOpt(Curl.option.HTTP2_PSEUDO_HEADERS_ORDER, 'mspa')

  curl.on('end', function (status, data, headers) {
    console.log(status)
    console.log(data)
    console.log(headers)
    this.close()
  })

  curl.perform()
}

main()
