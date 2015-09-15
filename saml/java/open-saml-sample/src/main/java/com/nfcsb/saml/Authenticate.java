package com.nfcsb.saml;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.LoggerFactory;

/**
 * Servlet implementation class
 */
public class Authenticate extends HttpServlet {

    private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(SamlUtils.class);
    private static final long serialVersionUID = 1L;

    /**
     * Default constructor.
     */
    public Authenticate() {
        // TODO Auto-generated constructor stub
    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
     * response)
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, UnsupportedEncodingException, IOException {

        String urlBase = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();

        String saml = SamlUtils.createAuthnRequetsString(urlBase + request.getContextPath() + "/Consume", "SSO Demo");

        Properties properties = SamlUtils.loadProperties();

        String targetURL = properties.getProperty("idpSsoTargetUrl");

        String reqString = targetURL + URLEncoder.encode(saml, "ASCII") + "&RelayState=null";

        LOG.debug("Redirect URL = " + reqString);
        response.sendRedirect(reqString);
    }

}
