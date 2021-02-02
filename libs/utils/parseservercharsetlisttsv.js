"use strict";

const fs = require("fs");
const https = require("https");

// Modified code from StackOverflow
// https://stackoverflow.com/questions/53963608/syntax-for-post-using-promisifyhttps
const getCharsetList = () => {
    return new Promise((resolve, reject) => {
        let data = Buffer.from([]);

        const req = https.get("https://raw.githubusercontent.com/rfc1036/whois/next/servers_charset_list", r => {
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
    let masterlisttsv = await getCharsetList();
    let finale = {};

    for (const line of masterlisttsv.split("\n")) {
        if (line.startsWith("#")) continue;
        let sp = line.split(/\s+/g).filter(s => !s.includes("#"));
        if (sp[0] === "" || sp.length === 0) continue;
        finale[sp[0]] = {
            encoding: sp[1] || "utf-8",
            quirk: "{{data}}"
        };
        if (sp[2] && sp[2].length > 0) {
            let optparam = sp.slice(2).join(" ");
            finale[sp[0]].quirk = `${optparam} {{data}}`;
        }
    }

    fs.writeFileSync("../charset-list.json", JSON.stringify(finale, null, 4));
};

main();