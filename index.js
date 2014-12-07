var url = require('url');
var fs = require('fs');
var https = require('https');
var crypto = require('crypto');

module.exports = {

    requestTicket: function(req, res, profile, certificate, proxyRestUri, targetId) {

        if (undefined == proxyRestUri) {
            var queryData = url.parse(req.url, true).query;
            proxyRestUri = queryData.proxyRestUri;
        }
        if (undefined == targetId) {
            var queryData = url.parse(req.url, true).query;
            targetId = queryData.targetId;
        }

        if (undefined == proxyRestUri || undefined == targetId)
        {
            res.end("Missing parameters");
            return;
        }

        if (undefined == certificate)
        {
            certificate = {
                'filename': './client.pfx',
                'passphrase': ''
            }
        }

        try {
            var cert = fs.readFileSync(certificate.filename);
        } catch (err) {
            res.end("Missing client certificate");
            return;
        }

        //Configure parameters for the ticket request
        var xrfkey = this.generateXrfkey();
        var options = {
            host: url.parse(proxyRestUri).hostname,
            port: url.parse(proxyRestUri).port,
            path: url.parse(proxyRestUri).path + '/ticket?xrfkey=' + xrfkey,
            method: 'POST',
            headers: { 'X-Qlik-Xrfkey': xrfkey, 'Content-Type': 'application/json' },
            pfx: cert,
            passphrase: certificate.passphrase,
            rejectUnauthorized: false,
            agent: false
        };

        //Send ticket request
        var ticketreq = https.request(options, function (ticketres) {
            ticketres.on('data', function (d) {
                //Parse ticket response
                var ticket = JSON.parse(d.toString());

                //Build redirect including ticket
                if (ticket.TargetUri.indexOf("?") > 0) {
                        redirectURI = ticket.TargetUri + '&QlikTicket=' + ticket.Ticket;
                    } else {
                        redirectURI = ticket.TargetUri + '?QlikTicket=' + ticket.Ticket;
                    }
                
                res.writeHead(302, {"Location": redirectURI});
                res.end();
            });
        });

        //Send JSON request for ticket
        var jsonrequest = JSON.stringify({ 'UserDirectory': profile.UserDirectory,
                                           'UserId': profile.UserId,
                                           'Attributes': profile.Attributes,
                                           'TargetId': targetId.toString()
                                       });
        ticketreq.write(jsonrequest);
        ticketreq.end();

        ticketreq.on('error', function (e) {
            console.error('Error' + e);
        });
    },

    generateXrfkey: function(size, chars) {
        size = size || 16;
        chars = chars || "abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789";

        var rnd = crypto.randomBytes(size), value = new Array(size), len = chars.length;

        for (var i = 0; i < size; i++) {
            value[i] = chars[rnd[i] % len]
        };

        return value.join('');
    }

};
