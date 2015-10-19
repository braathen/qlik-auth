WHAT IS QLIK-AUTH?

  qlik-auth is an attempt of simplyfing custom authentication with the Qlik
  Sense and QlikView products. This module for Node.js takes care of the ticket
  request and redirection. It allows a developer to focus on obtaining the user
  profile, provide it in a function call, and the rest will be automated.

REQUIREMENTS

 - Node.js (including npm) <https://nodejs.org>

INSTALLATION

    npm install qlik-auth

EXAMPLE

  This is just a minimal example to demonstrate how simple it is to use the
  module. The code below is from the Node.js website demonstrating how to run
  a webserver, with code added to handle a ticket request. This should only
  be seen as a demonstration and a way to get started. Normally you would for
  want to run the server as HTTPS and so on.

    var http = require('http');
    var qlikauth = require('qlik-auth');
    http.createServer(function (req, res) {

      //Define user directory, user identity and attributes
      var profile = {
        'UserDirectory': 'QLIK', 
        'UserId': 'rikard',
        'Attributes': [{'Group': 'ExampleGroup'}]
      }

      //Make call for ticket request
      qlikauth.requestTicket(req, res, profile);

    }).listen(1337, '0.0.0.0');
    console.log('Server running at http://localhost:1337/');

SETUP FOR QLIK SENSE

  Typically a custom authentication module in Qlik Sense would be called
  through a virtual proxy. Refer to Qlik Sense documentation how to set this
  up and configure it properly to access your custom built module.

 - In the example above a simple webserver is created with Node.js which
   listens on port 1337. This is the server and port you need to map in the
   virtual proxy configuration.

 - On Windows the module will attempt to use the QlikClient certificate in
   the Windows Certificate Store. If no certificate is not found it will
   then look for client.pfx and finally client.pem/client_key.pem in the
   current path.

 - Export the client certificates including the private key from QMC and copy
   it to the same directory as your script. If it's necessary to provide a
   password, see the Advanced section below.

ADVANCED USAGE

  The module exposes a function called requestTicket which has the following
  parameters:

    function(req, res, profile, options)

  The profile parameter:

    var profile = {
      'UserDirectory': 'QLIK', 
      'UserId': 'rikard',
      'Attributes': []
    }

  The options parameter:

 - In case the certificate is password protected it's possible to provide both
   the location and filename of the certificate together with a passphrase. It
   could look like this:

     var options = {
       'Certificate': './client.pfx',
       'PassPhrase': ''
     }

 - When Qlik Sense is redirecting to a custom authentication module it passes
   proxyRestUri and targetId as parameters. These are normally handled by the
   function automatically, but for scenarios where it might be necessary to
   redirect to another Identity Provider (IdP) for example, these parameters
   must be stored away and supplied manually.

     var options = {
       'ProxyRestUri': session.proxyRestUri,
       'TargetId': session.targetId
     }

  Optionally (or actually preferred method) could be to use the builtin
  init(req, res) function on your index page. This will attempt to save the
  parameters which the requestTicket function will later automatically pick up.

SETUP FOR QLIKVIEW

  QlikView would need to be configured for using webtickets, this includes
  changing Windows Authentication to Anonymous Authentication and configuring
  IP white lists as trust. Please refer to QlikView documentation how to do
  this.

ADVANCED USAGE

  The function to use for QlikView is called requestWebTicket and has the
  following parameters:

    function(req, res, profile, options)

  Where profile and options looks like this:

     var profile = {
       'UserDirectory': 'QLIK', 
       'UserId': 'rikard',
       'Groups': []
     }

 - UserDirectory: A domain prefix in QlikView, but should in most cases match
   a user directory.
 - UserId: The user identity which will be authenticated in QlikView.
 - Groups: An array of group memberships to include in the ticket request.

     var options = {
       'Host': 'http://localhost',
       'TryUrl': '/QlikView',
       'BackUrl': '',
       'Document': 'Movies Database'
     }

 - Host: Hostname, default is localhost (include http/https if specified)
 - TryUrl: Where you want to end up after succesfull authentication, in most
   cases this would be AccessPoint which is the default value.
 - BackUrl: Could be an error page or login page if authentication failed.
 - Document: A QlikView document, if specified it will bypass AccessPoint
   and go directly to the document.
