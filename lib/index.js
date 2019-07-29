const rp = require('request-promise')
const debug = require('debug')('gttx:sdk')

class GTTX {
  constructor(appId, secretKey, opts = {}) {
    this.appId = appId
    this.secretKey = secretKey
    this._timestampOfLastAuthorization = null
    this._authorization = null
    this._host = opts.host || 'cloud.gttx.com'
    this.protocol = opts.protocol || 'https'
    this.baseUrl = `${this.protocol}://${this._host}`
  }

  async _getAuthorization() {
    const now = parseInt(new Date() / 1000, 10)
    if (this._authorization &&
      this._timestampOfLastAuthorization &&
      now < this._timestampOfLastAuthorization + 60 * 25) {
        return this._authorization
      }

    return await this.authorize()
  }

  _setAuthorization(authorization) {
    this._timestampOfLastAuthorization = parseInt(new Date() / 1000, 10)
    this._authorization = authorization
    return this._authorization
  }

  /**
   * API 授权接口
   */
  async authorize() {
    const method = 'GET'
    const uri = '/xddos/public/authorize'
    const {appId, secretKey} = this
    const result = await this._request({
      method,
      uri,
      qs: {
        appId,
        secretKey
      }
    }, false)

    return this._setAuthorization(result.result.Authorization)
  }

  /**
   *
   * @param {!string} ipList - ip地址，英文逗号分隔，最多10个. 格式: 1.1.1.1,2.2.2.2
   * @param {!string} beginDate 格式：20190606010101
   * @param {!string} endDate 格式：20190605010101
   */
  async attacks(ipList, beginDate, endDate) {
    const method = 'GET'
    const uri = '/xddos/public/attacks'
    const result = await this._request({
      method,
      uri,
      qs: {
        ipList,
        beginDate,
        endDate
      }
    })

    return result.result
  }

  /**
   * CC攻击防护
   * @param {!string} ipList - ip地址，英文逗号分隔，最多10个. 格式: 1.1.1.1,2.2.2.2
   * @param {!string} beginDate - 格式：20190606010101
   * @param {!string} endDate - 格式：20190605010101
   */
  async ccAttacks(ipList, beginDate, endDate) {
    const method = 'GET'
    const uri = '/xddos/public/ccAttacks'
    const result = await this._request({
      method,
      uri,
      qs: {
        ipList,
        beginDate,
        endDate
      }
    })

    return result.result
  }

  /**
   * 攻击详情
   * @param {!string} ipList - ip地址，英文逗号分隔，最多10个. 格式: 1.1.1.1,2.2.2.2
   * @param {!string} beginDate - 格式：20190606010101
   * @param {!string} endDate - 格式：20190605010101
   */
  async attacksDetail(ipList, beginDate, endDate) {
    const method = 'GET'
    const uri = '/xddos/public/attacks/detail'
    const result = await this._request({
      method,
      uri,
      qs: {
        ipList,
        beginDate,
        endDate
      }
    })

    return result.result
  }

  /**
   * 流量清洗
   * @param {!string} ipList - 1.1.1.1,2.2.2.2
   * @param {!string} beginDate 20190606010101
   * @param {!string} endDate 20190605010101
   * @param {!string} level minute:分钟级 （时间跨度不超过1天） ，hour:小时级别 （跨度不超过7天），day:自然天级（跨度不超过30天）
   */
  async trendMap(ipList, beginDate, endDate, level) {
    const method = 'GET'
    const uri = '/xddos/public/trendMap'
    const result = await this._request({
      method,
      uri,
      qs: {
        ipList,
        beginDate,
        endDate,
        level
      }
    })

    return result.result
  }

  /**
   * 黑洞查询
   * @param {!string} ipList - ip 地址，英文逗号分隔，最多 50 个
   */
  async blackHoleStatus(ipList) {
    const method = 'GET'
    const uri = '/xddos/public/blackHoleStatus'
    const result = await this._request({
      method,
      uri,
      qs: {
        ipList
      }
    })

    return result.result
  }

  /**
   * 黑洞 IP 限时
   * @param {!string} ip - ip 地址
   * @param {!number} duration - 分钟单位
   */
  async blackHoleDuration(ip, duration) {
    const method = 'POST'
    const uri = '/xddos/public/blackHoleDuration'

    const result = await this._request({
      method,
      uri,
      qs: {
        ip,
        duration
      }
    })

    return result.result
  }

  /**
   * 黑洞限时查询
   * @param {!string} ipList - ip地址，英文逗号分隔，最多 50 个
   */
  async blackHoleDurationSearch(ipList) {
    const method = 'GET'
    const uri = '/xddos/public/blackHoleDurationSearch'

    const result = await this._request({
      method,
      uri,
      qs: {
        ipList
      }
    })

    return result.result
  }

  /**
   * 订单升级
   * @param {!string} orderCode - 订单编号
   * @param {!integer} minimumDdos - 提升的保底带宽
   * @param {!integer} threshold - 弹性带宽
   */
  async orderChange(orderCode, minimumDdos, threshold) {
    const method= 'POST'
    const uri = '/xddos/public/orderChange'

    const result = await this._request({
      method,
      uri,
      qs: {
        json: JSON.stringify({
          orderCode,
          minimumDdos,
          threshold,
        })
      },
    })

    return result.result
  }

  /**
   * 添加域名
   * @param {!string} domainName - 域名
   * @param {!boolean} siteType - 是否未网站类. true 网站类
   * @param {!stirng[]} vips 高防 ip
   * @param {?serviceConfig} serviceConfig - 非完整类可不传该值
   */
  async postDomain(domainName, siteType, vips = [], serviceConfig) {
    const method = 'POST'
    const uri = '/xddos/public/domain'

    const result = await this._request({
      method,
      uri,
      qs: {
        json: JSON.stringify({
          domainName,
          serviceConfig,
          siteType,
          vips,
        }),
      },
    })

    return result.result
  }

  /**
   * 删除域名
   * @param {!string} domainName
   */
  async deleteDomain(domainName) {
    const method = 'DELETE'
    const uri = `/xddos/public/domain/${domainName}`
    const result = await this._request({
      method,
      uri,
    })

    return result.result
  }

  /**
   * 修改域名
   * @param {!string} domainName
   * @param {?serviceConfig} serviceConfig
   */
  async patchDomain(domainName, serviceConfig) {
    const method = 'PATCH'
    const uri = '/xddos/public/domain'

    const result = await this._request({
      method,
      uri,
      qs: {
        json: JSON.stringify({
          domainName,
          serviceConfig
        }),
      },
      json: true,
    })

    return result.result
  }

  /**
   * 查询域名
   * @param {!string} domainList - 域名列表
   */
  async getDomain(domainList) {
    const method = 'GET'
    const uri = '/xddos/public/domain'

    const result = await this._request({
      method,
      uri,
      qs: {
        domainList,
      }
    })

    return result.result
  }


  async _request(opts, authorize = true) {
    const headers = authorize ? { Authorization: await this._getAuthorization() } : {}

    const data = await rp(Object.assign({
      baseUrl: this.baseUrl,
      headers,
      json: true,
    }, opts))

    debug(`${opts.method} ${opts.uri} respond with data`, data)

    if (data.apiStatus === 1) {
      const err = new Error(data.result.error_en)
      err.error_code = parseInt(data.result.error_code, 10)
      throw err
    }

    return data
  }
}

module.exports = GTTX

/**
 * @typedef serviceConfig
 * @desc 非网站类域名的服务配置
 * @param {?integer} httpEnable 是否开启 http 端口. 0: 开启 1: 关闭
 * @param {?string} httpPort - http 端口. 示例: 80
 * @param {?integer} httpsEnable - 是否开启 https 端口. 0: 开启 1: 关闭
 * @param {string} httpsPort - https 端口. 示例 443
 * @param {string[]} realServers - 源站 ip. 比如 ["3.3.3.3"]
 */
