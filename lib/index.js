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
   * @param {!string} ipList - 1.1.1.1,2.2.2.2
   * @param {!string} beginDate 20190606010101
   * @param {!string} endDate 20190605010101
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
