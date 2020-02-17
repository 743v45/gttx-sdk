const rp = require('request-promise')
const debug = require('debug')('gttx:sdk')
const retry = require('async-retry');

class GTTX {
  constructor(appId, secretKey, opts = {}) {
    this.appId = appId
    this.secretKey = secretKey
    this._timestampOfLastAuthorization = null
    this._authorization = null
    this._host = opts.host || 'cloud.gttx.com'
    this.protocol = opts.protocol || 'https'
    this.baseUrl = `${this.protocol}://${this._host}`
    this.unauthorizedRetry = opts.unauthorizedRetry || 0; // 默认不重试
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
   * IP 回源流量查询
   * @param {!string} ipList - IPv4 地址，英文逗号分隔，最多 10 个
   * @param {!string} beginDate - 开始时间 yyyyMMddHHmmss
   * @param {!string} endDate - 结束时间 yyyyMMddHHmmss
   * @param {!string} level - minute 分钟级别（跨度 1 天内） ｜ hour 小时级别（跨度 7 天内） ｜ day 自然天级别（跨度 30 天内）
   */
  async backSourceTrendMap(ipList, beginDate, endDate, level) {
    const uri = '/xddos/public/backSourceTrendMap';
    const method = 'GET';

    const result = await this._request({
      method,
      uri,
      qs: {
        ipList,
        beginDate,
        endDate,
        level,
      },
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
   * IP 总流量查询
   * @param {!string} ipList - 1.1.1.1,2.2.2.2
   * @param {!string} beginDate 20190606010101
   * @param {!string} endDate 20190605010101
   * @param {!string} level minute:分钟级 （时间跨度不超过1天） ，hour:小时级别 （跨度不超过7天），day:自然天级（跨度不超过30天）
   */
  async trendMapSum(ipList, beginDate, endDate, level) {
    const method = 'GET'
    const uri = '/xddos/public/trendMapSum'
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

  /**
   * 创建云防订单
   * @param {!object} data
   * @param {!string} data.code - 产品模型 code
   * @param {!number} data.ip - ip 个数
   * @param {?number} data.defend - 保底带宽（单位 Gbps）
   * @param {?number} data.elastic - 弹性带宽(单位 Gbps)
   * @param {?number} data.backFlow - 回源带宽(单位 Mbps)
   * @param {?number} data.line - 线路. 1.电信 2.电信+联通 3.电信联通移动 4.联通
   * @param {!number} data.location - 地区. 1.华东 2.华北 3.华南 4.西北
   * @param {!number} data.duration - 购买时长
   */
  async createCloudOrder(data) {
    const method = 'post';
    const uri = '/xddos/public/createCloudOrder';

    const result = await this._request({
      method,
      uri,
      qs: {
        json: JSON.stringify(data),
      },
    })

    return result.result
  }

  /**
   * 订单信息查询
   * @param {!string} code
   */
  async order(code) {
    const method = 'GET';
    const uri = `/xddos/public/order/${code}`;

    const result = await this._request({
      method,
      uri,
    })

    return result.result
  }

  /**
   * 订单信息批量查询
   */
  async orderList() {
    const method = 'GET';
    const uri = `/xddos/public/order`;


    const result = await this._request({
      method,
      uri,
    })

    return result.result
  }

  /**
   * 查询订单状态
   * @param {!string} code
   */
  async orderStatus(code) {
    const method = 'GET';
    const uri = '/xddos/public/orderStatus';

    const result = await this._request({
      method,
      uri,
      qs: {
        code,
      },
    })

    return result.result
  }

  /**
   * 防护带宽查询
   * @param {!string} ip
   */
  async bandWidth(ip) {
    const method = 'GET';
    const uri = '/xddos/public/bandWidth';
    const result = this._request({
      method,
      uri,
      qs: {
        ip,
      }
    })

    return result.result
  }

  /**
   * 添加高防转发规则
   * @param {!string} vip -高防 ip
   * @param {!string[]} portStrings -端口,不可与网站类使用的端口相同. 例：["99-101"],["99","100"]
   * @param {!string} ipProtocol - 协议 udp、tcp
   * @param {!string[]} sourcePortStrings - 源站端口
   * @param {!string[]} sourceIps - 源站 ip
   * @return {object} {"key":"ff80808163b52ffc0163b5d82f8200ec"}
   */
  async postIpRule(vip, portStrings, ipProtocol, sourcePortStrings, sourceIps) {
    const method = 'POST';
    const uri = '/xddos/public/ipRule';

    const result = await this._request({
      method,
      uri,
      qs: {
        json: JSON.stringify({
          vip,
          portStrings,
          ipProtocol,
          sourcePortStrings,
          sourceIps,
        }),
      },
      json: true,
    })

    return result.result
  }

  /**
   * 批量添加高防转发规则（v2）
   * @param {!string} vip -高防 ip
   * @param {!string[]} portStrings -端口,不可与网站类使用的端口相同. 例：["99-101"],["99","100"]
   * @param {!string} ipProtocol - 协议 udp、tcp
   * @param {!string[]} sourcePortStrings - 源站端口
   * @param {!string[]} sourceIps - 源站 ip
   * @return {object} {"key":"ff80808163b52ffc0163b5d82f8200ec"}
   */
  async postIpRuleV2(vip, portStrings, ipProtocol, sourcePortStrings, sourceIps) {
    const method = 'POST';
    const uri = '/xddos/public/ipRule/v2';

    const result = await this._request({
      method,
      uri,
      qs: {
        json: JSON.stringify({
          vip,
          portStrings,
          ipProtocol,
          sourcePortStrings,
          sourceIps,
        })
      },
      json: true,
    })

    return result.result
  }

  /**
   * 删除高防转发规则
   * @param {!string} vip - 高防 ip
   * @param {!number} ipPort - 端口
   * @param {!string} ipProtocol - 协议 udp、tcp
   * @return {object} {"key":"ff80808163b52ffc0163b5d82f8200ec"}
   */
  async deleteIpRule(vip, ipPort, ipProtocol) {
    const method = 'DELETE';
    const uri = '/xddos/public/ipRule';

    const result = await this._request({
      method,
      uri,
      qs: {
        json: JSON.stringify({
          ipPort,
          ipProtocol,
          vip,
        }),
      },
      json: true,
    })

    return result.result
  }

  /**
   * 修改高防转发规则
   * @param {!string} vip - 高防 ip
   * @param {!number} ipPort - 高防端口
   * @param {!string} ipProtocol - 协议 udp、tcp
   * @param {!number} sourceIpPort - 源站端口
   * @param {!string[]} sourceIps - 源站 ip
   * @return {object} {"key":"ff80808163b52ffc0163b5d82f8200ec"}
   */
  async patchIpRule(vip, ipPort, ipProtocol, sourceIpPort, sourceIps) {
    const method = 'PATCH';
    const uri = '/xddos/public/ipRule';

    const result = await this._request({
      method,
      uri,
      qs: {
        json: JSON.stringify({
          vip,
          ipPort,
          ipProtocol,
          sourceIpPort,
          sourceIps,
        })
      },
      json: true
    })

    return result.result
  }

  /**
   * 查询高防转发规则
   * @param {?string} ipList - IPv4 地址. 英文逗号分隔, 最多 50 个
   * @return {ipRule[]}
   */
  async getIpRule(ipList) {
    const method = 'GET';
    const uri = '/xddos/public/ipRule';

    const result = await this._request({
      method,
      uri,
      qs: {
        ipList,
      },
      json: true,
    })

    return result.result
  }

  /**
   * 查询高防配额使用情况
   * @param {!string} ip
   */
  async checkUsed(ip) {
    const method = 'GET';
    const uri = '/xddos/public/ipRule/checkUsed';
    const result = await this._request({
      method,
      uri,
      qs: {
        ip,
      },
      json: true,
    })

    return result.result
  }

  /**
   * 查询回源 IP 段
   * @param {!number} type - 回源类型 1 DDoS, 2 WAF
   * @param {?number} line - 线路（1.电信，2.联通，3.移动）
   * @param {?number} location - 地区（1.华东 2.华北 3.华南 4.西北）
   */
  async backSourceIp(type, line, location) {
    const method = 'GET';
    const uri = '/xddos/public/ipRule/checkUsed';
    const result = await this._request({
      method,
      uri,
      qs: {
        type,
        line,
        location,
      },
      json: true,
    })

    return result.result
  }

  /**
   * 查询记录处理进度
   * @param {!string} key - 调用域名解析和转发规则操作接口所返回的 key
   */
  async actionStatus(key) {
    const method = 'GET';
    const uri = `/xddos/public/action/status/${key}`;
    const result = await this._request({
      method,
      uri,
      json: true,
    })

    return result.result
  }



  async _request(opts, authorize = true) {
    return await retry(async (bail, times) => {
      const headers = authorize ? { Authorization: await this._getAuthorization(times) } : {}

      const data = await rp(Object.assign({
        baseUrl: this.baseUrl,
        headers,
        json: true,
      }, opts))

      debug(`${opts.method} ${opts.uri} respond with data at ${times} times`, data)

      if (data.apiStatus === 1) {
        const err = new Error(data.result.error_en)
        err.error_code = parseInt(data.result.error_code, 10)
        if (err.error_code !== 4) { // 仅重试授权失败的请求
          return bail(err);
        }

        throw err
      }

      return data
    }, {
      retries: this.unauthorizedRetry,
    });
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

/**
 * @typedef ipRule
 * @desc 高防转发规则
 * @param {string} vip - 高防 ip
 * @param {number} port - 高防 ip 端口
 * @param {number} protocol - 协议. 1 -> tcp, 2 -> udp
 * @param {number} status - 是否生效. 0 处理中， 1 已生效，2 处理失败
 * @param {string[]} realIps - 源站 ip
 * @param {number} sourceIpPort - 源站端口
 */
