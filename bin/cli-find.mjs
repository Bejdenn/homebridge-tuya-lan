#!/usr/bin/env node

import { Proxy } from 'http-mitm-proxy';
import EventEmitter from 'events';
import { Command } from 'commander';
import QRCode from 'qrcode';
import { resolve, join } from 'path';
import { networkInterfaces } from 'os';
import JSON5 from 'json5';
import { statSync, readFileSync } from 'fs';

// Disable debug messages from the proxy
try {
    require('debug').disable();
} catch (ex) { }

const ROOT = resolve(import.meta.dirname);

const pemFile = join(ROOT, 'certs', 'ca.pem');

let localIPs = Object.values(networkInterfaces()).flatMap(networks =>
    networks?.filter(network => network.family === 'IPv4').filter(network => !network.internal).map(network => network.address) || []
);

const proxy = new Proxy();
const emitter = new EventEmitter();

const program = new Command();

program.name('tuya-lan find')
    .option('--ip <ip>', 'IP address to listen for requests')
    .option('-p, --port <port>', 'port the proxy should listen on', 9567)
    .option('--schema', 'include schema in the output')

program.parse();

const options = program.opts();

if (options.ip) {
    if (localIPs.includes(options.ip)) localIPs = [options.ip];
    else {
        console.log(`The requested IP, ${options.ip}, is not a valid external IPv4 address. The valid options are:\n\t${localIPs.join('\n\t')}`);
        process.exit();
    }
}
if (localIPs.length > 1) {
    console.log(`You have multiple network interfaces: ${localIPs.join(', ')}\nChoose one by passing it with the --ip parameter.\n\nExample: tuya-lan-find --ip ${localIPs[0]}`);
    process.exit();
}
const localIPPorts = localIPs.map(ip => `${ip}:${options.port}`);

const escapeUnicode = str => str.replace(/[\u00A0-\uffff]/gu, c => "\\u" + ("000" + c.charCodeAt().toString(16)).slice(-4));

proxy.onError(function(_ctx, err) {
    switch (err.code) {
        case 'ERR_STREAM_DESTROYED':
        case 'ECONNRESET':
            return;

        case 'ECONNREFUSED':
            console.error('Failed to intercept secure communications. This could happen due to bad CA certificate.');
            return;

        case 'EACCES':
            console.error(`Permission was denied to use port ${options.port}.`);
            return;

        default:
            console.error('Error:', err.code, err);
    }
});

proxy.onRequest(function(ctx, callback) {
    if (ctx.clientToProxyRequest.method === 'GET' && ctx.clientToProxyRequest.url === '/cert' && localIPPorts.includes(ctx.clientToProxyRequest.headers.host)) {
        ctx.use(Proxy.gunzip);
        console.log('Intercepted certificate request');

        ctx.proxyToClientResponse.writeHeader(200, {
            'Accept-Ranges': 'bytes',
            'Cache-Control': 'public, max-age=0',
            'Content-Type': 'application/x-x509-ca-cert',
            'Content-Disposition': 'attachment; filename=cert.pem',
            'Content-Transfer-Encoding': 'binary',
            'Content-Length': statSync(pemFile).size,
            'Connection': 'keep-alive',
        });
        //ctx.proxyToClientResponse.end(fs.readFileSync(path.join(ROOT, 'certs', 'ca.pem')));
        ctx.proxyToClientResponse.write(readFileSync(pemFile));
        ctx.proxyToClientResponse.end();

        return;

    } else if (ctx.clientToProxyRequest.method === 'POST' && /tuya/.test(ctx.clientToProxyRequest.headers.host)) {
        ctx.use(Proxy.gunzip);

        ctx.onRequestData(function(_ctx, chunk, callback) {
            return callback(null, chunk);
        });
        ctx.onRequestEnd(function(_ctx, callback) {
            callback();
        });

        let chunks = [];
        ctx.onResponseData(function(_ctx, chunk, callback) {
            chunks.push(chunk);
            return callback(null, chunk);
        });
        ctx.onResponseEnd(function(_ctx, callback) {
            emitter.emit('tuya-config', Buffer.concat(chunks).toString());
            callback();
        });
    }

    return callback();
});

emitter.on('tuya-config', body => {
    if (body.indexOf('tuya.m.my.group.device.list') === -1) return;
    console.log('Intercepted config from Tuya');
    let data;
    const fail = (msg, err) => {
        console.error(msg, err);
        process.exit(1);
    };
    try {
        data = JSON.parse(body);
    } catch (ex) {
        return fail('There was a problem decoding config:', ex);
    }
    if (!Array.isArray(data.result)) return fail('Couldn\'t find a valid result-set.');

    let devices = [];
    data.result.some(data => {
        if (data && data.a === 'tuya.m.my.group.device.list') {
            devices = data.result;
            return true;
        }
        return false;
    });

    if (!Array.isArray(devices)) return fail('Couldn\'t find a good list of devices.');

    console.log(`\nFound ${devices.length} device${devices.length === 1 ? '' : 's'}:`);

    const foundDevices = devices.map(device => {
        return {
            name: device.name,
            id: device.devId,
            key: device.localKey,
            pid: device.productId
        }
    });

    if (options.schema) {
        let schemas = [];
        data.result.some(data => {
            if (data && data.a === 'tuya.m.device.ref.info.my.list') {
                schemas = data.result;
                return true;
            }
            return false;
        });

        if (Array.isArray(schemas)) {
            const defs = {};
            schemas.forEach(schema => {
                if (schema.id && schema.schemaInfo) {
                    defs[schema.id] = {};
                    if (schema.schemaInfo.schema) defs[schema.id].schema = escapeUnicode(schema.schemaInfo.schema);
                    if (schema.schemaInfo.schemaExt && schema.schemaInfo.schemaExt !== '[]') defs[schema.id].extras = escapeUnicode(schema.schemaInfo.schemaExt);
                }
            });
            foundDevices.forEach(device => {
                if (defs[device.pid]) device.def = defs[device.pid];
            });
        } else console.log('Didn\'t find schema definitions. You will need to identify the data-points manually if this is a new device.');
    }

    foundDevices.forEach(device => {
        delete device.pid;
    });

    console.log(JSON5.stringify(foundDevices, '\n', 2));

    setTimeout(() => {
        process.exit(0);
    }, 5000);
});

proxy.listen({ host: localIPs[0], port: options.port, sslCaDir: ROOT }, err => {
    if (err) {
        console.error('Error starting proxy: ' + err);
        return setTimeout(() => {
            process.exit(0);
        }, 5000);
    }
    let { address, port } = proxy.httpServer.address();

    const proxyUrl = `http://${address}:${port}/cert`;
    QRCode.toString(proxyUrl, { type: 'terminal' }, function(err, url) {
        if (err) {
            console.error('Failed to generate QR code:', err);
            return;
        }

        console.log(url);
        console.log('Scan the QR code above to install the certificate on your device.');
        console.log('If you can\'t scan the QR code, you can download the certificate from: ' + proxyUrl);
    })
});
