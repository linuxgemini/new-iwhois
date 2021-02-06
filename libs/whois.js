/**
 * Simple(?) WHOIS Client
 * @author linuxgemini
 * @license
 * Copyright 2020 İlteriş Yağıztegin Eroğlu (linuxgemini)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

"use strict";

const chardet = require("chardet");
const iconv = require("iconv-lite");
const ipaddress = require("ip-address");
const net = require("net");

class whoisClient {
    constructor() {
        this.__recurseLimit = 10;
        this.__nicHandleWhoisList = require("./nic-handle-list.json");
        this.__domainWhoisList = require("./domain-whois-list.json");
        this.__extQuirks = require("./charset-list.json");
        this.__quirks = {
            "whois.ripe.net": "{{data}} -B",
            "whois.afrinic.net": "{{data}} -B",
        };
        this.__asnQuirks = {
            "whois.arin.net": "a {{data}}"
        };
        this.__ipQuirks = {
            "whois.arin.net": "n + {{data}}"
        };
    }

    /**
     * @param {string} str
     * @returns {string}
     */
    __strStrip(str) {
        return str.replace(/^\s+|\s+$/g, "");
    }

    /**
     * @param {string} data
     * @returns {string}
     */
    __cleanupData(data) {
        return this.__strStrip(data.replace(/\r\n/g, "\n"));
    }

    /**
     * dedupe refers by key
     * from https://stackoverflow.com/a/56768137
     * @param {any[]} arr 
     * @param {*} key 
     */
    __dedupeRefers(arr, key) {
        return [...new Map(arr.map(item => [item[key], item])).values()];
    }

    /**
     * @param {string} str
     * @returns {boolean}
     */
    __isIP(str) {
        let v4 = ipaddress.Address4.isValid(str);
        let v6 = ipaddress.Address6.isValid(str);
        return v4 || v6;
    }

    /**
     * @param {string} data
     * @returns {Array.<{host: string, port: number}>}
     */
    __returnRefers(data) {
        let splitter = (data.includes("\r\n") ? "\r\n" : "\n");
        let dataLines = data.split(splitter);

        /** @type {string[]} */
        let whoisServersRaw = [];

        /** @type {string[]} */
        let whoisServers = [];

        for (const line of dataLines) {
            if (line.startsWith("%") || line.startsWith("#")) continue;
            if (line.length === 0 || line.match(/^\s+$/)) continue;
            let lineStrip = this.__strStrip(line);
            if (lineStrip.startsWith("refer:") || lineStrip.startsWith("whois:") || lineStrip.startsWith("ReferralServer:")) {
                let stripped = this.__strStrip(line.split(" ").slice(1).join(" "));
                if (stripped !== "") whoisServersRaw.push(stripped.toLowerCase());
            }
            if (lineStrip.match(/^\w+ WHOIS Server: /i)) {
                let strippassone = this.__strStrip(line).replace(/^\w+ WHOIS Server: /i, "");
                if (strippassone !== "") whoisServersRaw.push(strippassone.toLowerCase());
            }
        }

        for (const server of whoisServersRaw) {
            let srv = server
                .replace(/^(r?whois):\/\//, "")
                .toLowerCase();
            let srvport = 43;

            if (srv.includes(":")) {
                let srvparts = server.split(":");
                let srvpartsLastItem = srvparts[srvparts.length - 1];
                if (srvpartsLastItem.endsWith("]") || !srvpartsLastItem.match(/^:(\d{1,5}$)/)) {
                    srv = server;
                } else {
                    srv = srv.replace(/:\d{1,5}$/, "");
                    srvport = parseInt(srvpartsLastItem.match(/^:(\d{1,5}$)/)[1], 10);
                }
            }

            whoisServers.push({
                host: srv,
                port: srvport
            });
        }

        return this.__dedupeRefers(whoisServers, "host");
    }

    /**
     * @param {string} host
     * @param {string} querydata
     * @param {number?} port
     * @returns {Promise<string>}
     */
    __makeQuery(host, querydata, port = 43) {
        return new Promise((resolve, reject) => {
            let data = Buffer.from([]);

            const client = new net.Socket();

            client.setTimeout(4000);

            client.on("data", (chunk) => {
                data = Buffer.concat([data, chunk]);
            });

            client.on("timeout", () => {
                return reject(new Error("Connection Timeout"));
            });

            client.on("error", (e) => {
                return reject(e);
            });

            client.on("close", (had_err) => {
                if (had_err) return reject(new Error("Connection closed with Error"));

                let encoding = (this.__extQuirks[host] ? this.__extQuirks[host].encoding : chardet.detect(data));
                return resolve(iconv.decode(data, encoding));
            });

            client.connect({
                host,
                port
            }, () => {
                client.write(`${querydata}\r\n`);
            });
        });
    }

    /**
     * @param {string} data
     */
    __whoisServerPass(data) {
        let server = "whois.iana.org";
        data = data.toLowerCase();

        for (const tld of Object.keys(this.__domainWhoisList)) {
            if (data.endsWith(tld)) {
                server = this.__domainWhoisList[tld];
                break;
            }
        }

        for (const nicHandle of Object.keys(this.__nicHandleWhoisList)) {
            if (data.endsWith(nicHandle)) {
                server = this.__nicHandleWhoisList[nicHandle];
                break;
            }
        }

        return server;
    }

    /**
     * @param {string} host
     * @param {string} data
     */
    __quirkPass(host, data) {
        let quirkFixedData;
        if (this.__extQuirks[host]) quirkFixedData = this.__extQuirks[host].quirk.replace("{{data}}", data);
        if (this.__quirks[host]) quirkFixedData = this.__quirks[host].replace("{{data}}", (quirkFixedData || data));
        if (this.__asnQuirks[host] && data.match(/^AS\d{1,10}/i)) quirkFixedData = this.__asnQuirks[host].replace("{{data}}", (quirkFixedData || data).replace(/^AS/i, ""));
        if (this.__ipQuirks[host] && this.__isIP(data)) quirkFixedData = this.__ipQuirks[host].replace("{{data}}", data);

        return (quirkFixedData || data);
    }

    /**
     * @param {string} data
     * @param {number} recursed
     * @param {string?} currHost
     * @param {string[]?} prevHosts
     * @param {string?} prevData
     * @param {number?} port
     */
    async queryRecursive(data, recursed = 0, currHost = null, prevHosts = null, prevData = null, port = 43) {
        let host = (recursed > 0 ? currHost : this.__whoisServerPass(data));
        let fixedData = this.__quirkPass(host, data);
        if (prevHosts === null) prevHosts = [host];

        let res;

        try {
            res = await this.__makeQuery(host, fixedData, port);
            res = this.__cleanupData(res);
        } catch (e) {
            if (prevData) {
                return `%#% ${e.message} on host "${host}", returning data from "${prevHosts[1]}"\n\n${prevData}`;
            } else {
                throw e;
            }
        }

        let refs = this.__returnRefers(res);
        let refHosts = refs.map(h => h.host);
        let refPorts = refs.map(p => p.port);

        if (recursed === this.__recurseLimit) {
            return res;
        } else if (refHosts && refHosts[0] && (refHosts[0] !== host || !prevHosts.includes(refHosts[0])) && refPorts[0] === 43) {
            return await this.queryRecursive(data, (recursed + 1), refHosts[0], [refHosts[0], ...prevHosts], res, refPorts[0]);
        } else {
            return res;
        }
    }

    /**
     * @param {string} data
     * @param {number} recursed
     * @param {string?} currHost
     * @param {string[]?} prevHosts
     * @param {string?} prevData
     * @param {number?} port
     * @param {Array.<{host: string, port: number}>?} undoneRefs
     */
    async queryRecursiveVerbose(data, recursed = 0, currHost = null, prevHosts = null, prevData = null, port = 43, undoneRefs = null) {
        let host = (recursed > 0 ? currHost : this.__whoisServerPass(data));
        let fixedData = this.__quirkPass(host, data);
        if (prevHosts === null) prevHosts = [host];

        let res;

        try {
            res = await this.__makeQuery(host, fixedData, port);
            res = this.__cleanupData(res);
        } catch (e) {
            if (prevData) {
                return `${prevData}\n%#% ${e.message} on host "${host}"`;
            } else {
                throw e;
            }
        }

        let refs = this.__returnRefers(res);
        let refHosts = refs.map(h => h.host);
        let refPorts = refs.map(p => p.port);
        let undonerefHosts;
        let undonerefPorts;

        if (prevData) res = `${prevData}\n\n\n${res}`;
        if (undoneRefs) {
            undonerefHosts = undoneRefs.map(h => h.host);
            undonerefPorts = undoneRefs.map(p => p.port);
        }

        if (recursed === this.__recurseLimit) {
            return res;
        } else if (refHosts && refHosts[0] && (refHosts[0] !== host || !prevHosts.includes(refHosts[0]))) {
            res = `${res}\n\n\n%#% Found referrals to '${JSON.stringify(refHosts)}', trying the first host ("${refHosts[0]}")`;
            return await this.queryRecursiveVerbose(data, (recursed + 1), refHosts[0], [refHosts[0], ...prevHosts], res, refPorts[0], refs.slice(1));
        } else if (undonerefHosts && undonerefHosts[0] && (undonerefHosts[0] !== host || !prevHosts.includes(undonerefHosts[0]))) {
            res = `${res}\n\n\n%#% Already have referrals to '${JSON.stringify(undonerefHosts)}', trying the first host ("${undonerefHosts[0]}")`;
            return await this.queryRecursiveVerbose(data, (recursed + 1), undonerefHosts[0], [undonerefHosts[0], ...prevHosts], res, undonerefPorts[0], undoneRefs.slice(1));
        } else {
            return res;
        }
    }

    /**
     * @param {string} data
     */
    async queryRIPE(data) {
        let host = "whois.ripe.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return this.__cleanupData(res);
    }

    /**
     * @param {string} data
     */
    async queryARIN(data) {
        let host = "whois.arin.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return this.__cleanupData(res);
    }

    /**
     * @param {string} data
     */
    async queryAFRINIC(data) {
        let host = "whois.afrinic.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return this.__cleanupData(res);
    }

    /**
     * @param {string} data
     */
    async queryAPNIC(data) {
        let host = "whois.apnic.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return this.__cleanupData(res);
    }

    /**
     * @param {string} data
     */
    async queryLACNIC(data) {
        let host = "whois.lacnic.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return this.__cleanupData(res);
    }

    /**
     * @param {string} data
     */
    async queryRADb(data) {
        let host = "whois.radb.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return this.__cleanupData(res);
    }
}

module.exports = whoisClient;
