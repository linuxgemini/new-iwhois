"use strict";

const fs = require("fs");
const https = require("https");

// Modified code from StackOverflow
// https://stackoverflow.com/questions/53963608/syntax-for-post-using-promisifyhttps
const getServList = () => {
    return new Promise((resolve, reject) => {
        let data = Buffer.from([]);

        const req = https.get("https://raw.githubusercontent.com/rfc1036/whois/next/tld_serv_list", r => {
            r.on("data", (chunk) => {
                data = Buffer.concat([data, chunk]);
            });

            r.on("timeout", () => {
                return reject(new Error("Connection Timeout"));
            });

            r.on("end", () => {
                if (r.statusCode === 200) {
                    resolve(data.toString("utf8"));
                } else {
                    reject(new Error("Response indicated failure"));
                }
            });
        }).on("error", (err) => {
            reject(err);
        });

        req.end();
    });
};

const main = async () => {
    /** @type {string} */
    let masterlisttsv = await getServList();
    let finale = {};

    for (const line of masterlisttsv.split("\n")) {
        if (line.startsWith("#")) continue;
        let sp = line.split(/\s+/g).filter(s => !s.includes("#"));
        if (sp[0] === "" || sp.length === 0) continue;
        switch (sp[1]) {
            case "WEB":
                break;
            case "NONE":
                break;
            case "AFILIAS":
                finale[sp[0]] = "whois.afilias-grs.info";
                break;
            case "VERISIGN":
                finale[sp[0]] = (sp[2] || "whois.verisign-grs.com");
                break;
            case "ARPA":
                break;
            case "IP6":
                break;
            default:
                finale[sp[0]] = sp[1];
                break;
        }
    }

    fs.writeFileSync("../domain-whois-list.json", JSON.stringify(finale, null, 4));
};

main();