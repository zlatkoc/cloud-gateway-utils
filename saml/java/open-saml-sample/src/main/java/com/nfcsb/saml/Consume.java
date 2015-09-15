package com.nfcsb.saml;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.saml2.core.Response;
import org.slf4j.LoggerFactory;

/**
 * Servlet implementation class 
 */
public class Consume extends HttpServlet {
	private static final long serialVersionUID = 1L;
        
        private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(SamlUtils.class);
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public Consume() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		java.io.PrintWriter writer = response.getWriter();
                
                
                String samlResponse = request.getParameter("SAMLResponse");
                Response r = SamlUtils.parseAndUnmarshall(samlResponse);
                
                if (r != null) {
                    try {
                        SamlUtils.validate(r);
                        writer.write("SUCCESS\n");
                        writer.write("ID = " + SamlUtils.getNameID(r));
                    } catch (Exception ex) {
                        LOG.error("Vallidation failed" + ex);
                        writer.write("SIGINATURE VALIDATION FAILED:"  + ex);
                    }
                    
                } else {
                    writer.write("FAILED");
                }
	}
}
