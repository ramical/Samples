(function () {

    // The HTML for this View
    var viewHTML;
    // Instantiate the ADAL AuthenticationContext
    var authContext = new AuthenticationContext(config);

    function refreshViewData() {
        // Empty Old View Contents
        var $dataContainer = $(".data-container");
        $dataContainer.empty();
        var $loading = $(".view-loading");

        // Acquire Token for Backend
        authContext.acquireToken(authContext.config.clientId, function (error, token) {
            // Handle ADAL Error
            if (error || !token) {
                printErrorMessage('ADAL Error Occurred: ' + error);
                return;
            }

            // Get JWT2SAML Data
            $.ajax({
                type: "GET",
                url: "/api/JWT2SAMLTransition",
                headers: {
                    'Authorization': 'Bearer ' + token,
                },
            }).done(function (jwt2samlTransition) {
                var $html = $(viewHTML);
                var $entry = $html.find(".data-container");
                var output = '';
                $loading.hide();

                //JWT
                $entry.find(".view-data-property").html('JWT');
                $entry.find(".view-data-value").html(jwt2samlTransition.JWT);
                output += $entry.html();

                //Decoded JWT
                $entry.find(".view-data-property").html('DecodedJWT');
                var decodedJWT = JSON.stringify(JSON.parse(atob(jwt2samlTransition.JWT.split('.')[1])));
                $entry.find(".view-data-value").html(decodedJWT);
                output += $entry.html();

                ////SAML Token
                $entry.find(".view-data-property").html('SAMLToken');
                $entry.find(".view-data-value").html(jwt2samlTransition.SAMLToken);
                output += $entry.html();

                ////Decoded SAML Token
                $entry.find(".view-data-property").html('DecodedSAMLToken');

                //pretty print SAML Token
                var decodedSamlToken = formatXml(jwt2samlTransition.DecodedSAMLToken);
                decodedSamlToken = decodedSamlToken.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');//.replace(/ /g, '&nbsp;');//.replace(/\n/g, '<br />')

                $entry.find(".view-data-value").html(decodedSamlToken);
                output += $entry.html();

                $dataContainer.html(output);

            }).fail(function () {
                printErrorMessage('Error getting JWT 2 SAML Information')
            }).always(function () {
            });
        });
    };

    function registerDataClickHandlers() {
    };

    function registerViewClickHandlers() {
        // Add Button
    };

    function clearErrorMessage() {
        var $errorMessage = $(".app-error");
        $errorMessage.empty();
    };

    function printErrorMessage(mes) {
        var $errorMessage = $(".app-error");
        $errorMessage.html(mes);
    }

    //from: https://gist.github.com/sente/1083506/d2834134cd070dbcc08bf42ee27dabb746a1c54d
    function formatXml(xml) {
        var formatted = '';
        var reg = /(>)(<)(\/*)/g;
        xml = xml.replace(reg, '$1\r\n$2$3');
        var pad = 0;
        jQuery.each(xml.split('\r\n'), function (index, node) {
            var indent = 0;
            if (node.match(/.+<\/\w[^>]*>$/)) {
                indent = 0;
            } else if (node.match(/^<\/\w/)) {
                if (pad != 0) {
                    pad -= 1;
                }
            } else if (node.match(/^<\w[^>]*[^\/]>.*$/)) {
                indent = 1;
            } else {
                indent = 0;
            }

            var padding = '';
            for (var i = 0; i < pad; i++) {
                padding += '  ';
            }

            formatted += padding + node + '\r\n';
            pad += indent;
        });

        return formatted;
    }

    // Module
    window.homeCtrl = {
        requireADLogin: true,
        preProcess: function (html) {
        },
        postProcess: function (html) {
            viewHTML = html;
            refreshViewData();
        },
    };
}());

