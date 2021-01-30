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
     * @returns {boolean}
     */
    __isIP(str) {
        let v4 = ipaddress.Address4.isValid(str);
        let v6 = ipaddress.Address6.isValid(str);
        return v4 || v6;
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
                .replace(/^r?whois:\/\//, "")
                .replace(/:\d{1,5}$/, "")
                .toLowerCase();
            let srvport = 43;

            if (server.includes(":")) {
                let srvparts = server.split(":");
                let srvpartsLastItem = srvparts[srvparts.length - 1];
                if (srvpartsLastItem.match(/^[0-9]{1,5}$/) && !srvpartsLastItem.includes("]")) srvport = parseInt(srvpartsLastItem, 10);
            }

            whoisServers.push({
                host: srv,
                port: srvport
            });
        }

        return [...new Set(whoisServers)];
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

            client.setTimeout(3000);

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
        let host = (recursed > 0 ? currHost : "whois.iana.org");
        let fixedData = this.__quirkPass(host, data);
        if (prevHosts === null) prevHosts = [host];

        let res;

        try {
            res = await this.__makeQuery(host, fixedData, port);
            res = res.replace(/\r\n/g, "\n").replace(/^\n+/g, "").replace(/\n+$/g, "");
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

        if (recursed === 10) {
            return res;
        } else if (refHosts[0] && (refHosts[0] !== host || !prevHosts.includes(refHosts[0])) && refPorts[0] === 43) {
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
        let host = (recursed > 0 ? currHost : "whois.iana.org");
        let fixedData = this.__quirkPass(host, data);
        if (prevHosts === null) prevHosts = [host];

        let res;

        try {
            res = await this.__makeQuery(host, fixedData, port);
            res = res.replace(/\r\n/g, "\n").replace(/^\n+/g, "").replace(/\n+$/g, "");
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

        if (recursed === 10) {
            return res;
        } else if (refHosts[0] && (refHosts[0] !== host || !prevHosts.includes(refHosts[0]))) {
            res = `${res}\n\n\n%#% Found referrals to '${JSON.stringify(refHosts)}', trying the first host ("${refHosts[0]}")`;
            return await this.queryRecursiveVerbose(data, (recursed + 1), refHosts[0], [refHosts[0], ...prevHosts], res, refPorts[0], refs.slice(1));
        } else if (undonerefHosts[0] && (undonerefHosts[0] !== host || !prevHosts.includes(undonerefHosts[0]))) {
            res = `${res}\n\n\n%#% Already have referrals to '${JSON.stringify(undonerefHosts)}', trying the first host ("${undonerefHosts[0]}")`;
            return await this.queryRecursiveVerbose(data, (recursed + 1), undonerefHosts[0], [undonerefHosts[0], ...prevHosts], res, undonerefPorts[0], undoneRefs.slice(1));
        } else {
            return res;
        }
    }

    async queryRIPE(data) {
        let host = "whois.ripe.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return res;
    }

    async queryARIN(data) {
        let host = "whois.arin.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return res;
    }

    async queryAFRINIC(data) {
        let host = "whois.afrinic.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return res;
    }

    async queryAPNIC(data) {
        let host = "whois.apnic.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return res;
    }

    async queryLACNIC(data) {
        let host = "whois.lacnic.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return res;
    }

    async queryRADb(data) {
        let host = "whois.radb.net";
        let fixedData = this.__quirkPass(host, data);

        let res = await this.__makeQuery(host, fixedData);

        return res;
    }
}

module.exports = whoisClient;
