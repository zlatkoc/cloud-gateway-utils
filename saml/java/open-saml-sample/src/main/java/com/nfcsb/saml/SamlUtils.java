package com.nfcsb.saml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Properties;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;




public class SamlUtils {
    
    private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(SamlUtils.class);
    
    public static Properties config;

    /**
     * Initialize OpenSaml & config properties
     */
    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }
        
        try {
            config = loadProperties();
        } catch (IOException ex) {
            LOG.error("Failed to load properties !", ex);
        }
    }

    public static String createAuthnRequetsString(String consumerURL, String spName)  {

        try {
            AuthnRequest authnRequest = createAuthnRequestSAMLObject(consumerURL, spName);
            
            String samlString = marshall(authnRequest);
            
            LOG.debug("AuthnRequest = " + samlString);
            
            String encodedString = deflateAndBase64Encode(samlString);
            
            LOG.debug("Encoded AuthnRequest = " + encodedString);
            
            return encodedString;
        } catch (IllegalArgumentException e) {
            LOG.error("Error creating request string",  e);
        } catch (IllegalAccessException e) {
            LOG.error("Error creating request string",  e);
        } catch (NoSuchFieldException e) {
            LOG.error("Error creating request string",  e);
        } catch (SecurityException e) {
            LOG.error("Error creating request string",  e);
        } catch (MessageEncodingException e) {
            LOG.error("Error creating request string",  e);
        }
        
        return null;
    }
    
    public static AuthnRequest createAuthnRequestSAMLObject(String consumerURL, String sPName) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException {
        
        // Create AuthnRequest element
        AuthnRequest authnRequest = createSAMLObject(AuthnRequest.class);
        authnRequest.setForceAuthn(false);
        authnRequest.setIsPassive(false);
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setProviderName(sPName);
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        authnRequest.setAssertionConsumerServiceURL(consumerURL);
        authnRequest.setID(UUID.randomUUID().toString());

        // Create Issuer element
        Issuer issuer = createSAMLObject(Issuer.class);
        issuer.setValue(sPName);
        
        authnRequest.setIssuer(issuer);

        // Create NameIDPolicy element
        NameIDPolicy nameIDPolicy = createSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");

        authnRequest.setNameIDPolicy(nameIDPolicy);

        return authnRequest;
    }

    public static Element marshallMessage(XMLObject message)
            throws MessageEncodingException {
        try {
            org.opensaml.xml.io.Marshaller marshaller = Configuration.getMarshallerFactory()
                    .getMarshaller(message);
            if (marshaller == null) {
                throw new MessageEncodingException(
                        "Unable to marshall message, no marshaller registered for message object: "
                        + message.getElementQName());
            }

            Element messageElem = marshaller.marshall(message);
            return messageElem;
        } catch (MarshallingException e) {
            throw new MessageEncodingException(
                    "Encountered error marshalling message into its DOM representation",
                    e);
        }
    }

    public static String deflateAndBase64Encode(SAMLObject message)
            throws MessageEncodingException {
        try {
            String messageStr = XMLHelper
                    .nodeToString(marshallMessage(message));

            ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            Deflater deflater = new Deflater(8, true);
            DeflaterOutputStream deflaterStream = new DeflaterOutputStream(
                    bytesOut, deflater);
            //deflaterStream.write(messageStr.getBytes("UTF-8"));
            deflaterStream.write(messageStr.getBytes("ASCII"));
            deflaterStream.finish();

            return Base64.encodeBytes(bytesOut.toByteArray(), 8);
        } catch (IOException e) {
            throw new MessageEncodingException(
                    "Unable to DEFLATE and Base64 encode SAML message", e);
        }
    }

    public static String deflateAndBase64Encode(String messageStr)
            throws MessageEncodingException {
        try {

            ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            Deflater deflater = new Deflater(8, true);
            DeflaterOutputStream deflaterStream = new DeflaterOutputStream(
                    bytesOut, deflater);
            //deflaterStream.write(messageStr.getBytes("UTF-8"));
            deflaterStream.write(messageStr.getBytes("ASCII"));
            deflaterStream.finish();

            return Base64.encodeBytes(bytesOut.toByteArray(), 8);
        } catch (IOException e) {
            throw new MessageEncodingException(
                    "Unable to DEFLATE and Base64 encode SAML message", e);
        }
    }

    public static String marshall(SAMLObject message) throws MessageEncodingException {
        String messageStr = XMLHelper.nodeToString(marshallMessage(message));
        return messageStr;
    }

    /**
     * Utility method for creating SAML objects
     * @param <T>
     * @param clazz
     * @return
     * @throws IllegalArgumentException
     * @throws IllegalAccessException
     * @throws NoSuchFieldException
     * @throws SecurityException 
     */
    public static <T> T createSAMLObject(final Class<T> clazz) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException {
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

        QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
        @SuppressWarnings("unchecked")
        T object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);

        return object;
    }
    
    /**
     * Decode response from base64, parse XML and unmarshall to SAML Response 
     * 
     * @param samlResponse B64 encoded string
     * @return 
     */

    public static Response parseAndUnmarshall(String samlResponse){

        try {
            
            // decode response string from b64
            byte[] decodedB = Base64.decode(samlResponse);
            
            
            // parse XML
            BasicParserPool ppMgr = new BasicParserPool();
            ppMgr.setNamespaceAware(true);
            Document doc = ppMgr.parse(new ByteArrayInputStream(decodedB));
            
            Element rootElem = doc.getDocumentElement();
            LOG.debug("XML Document = " + XMLHelper.nodeToString(rootElem));
            
            // Get apropriate unmarshaller
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(rootElem);
            
            // Unmarshall using the document root element
            Response response = (Response) unmarshaller.unmarshall(rootElem);
            
            return response;
            
        } catch (XMLParserException e) {
                LOG.error("XML parsing error: ", e);
        } catch (UnmarshallingException e) {
            LOG.error("XML parsing error: ", e);
        }
        
        return null;
    }
    
    /**
     * Validate response with public key stored in keystore.jks
     * 
     * @param response
     * @throws KeyStoreException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     * @throws org.opensaml.xml.security.SecurityException
     * @throws ValidationException 
     */

    public static void validate(Response response) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException, org.opensaml.xml.security.SecurityException, ValidationException {
        
        // load keystore
        KeyStore keystore;
        keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream inputStream = SamlUtils.class.getResourceAsStream("/keystore.jks");
        keystore.load(inputStream, "changeit".toCharArray());
        inputStream.close();

        // get public key with alias defined in config from keystore
        Certificate certificate = keystore.getCertificate(config.getProperty("certificateAlias"));
        PublicKey publicKey = certificate.getPublicKey();

        // create credentials with public key
        BasicCredential credential = new BasicCredential();
        credential.setPublicKey(publicKey);

        // validate response
        SignatureValidator sigValidator = new SignatureValidator(credential);
        sigValidator.validate(response.getSignature());

    }

    public static String getNameID(Response r) {

        for (Assertion assertion : r.getAssertions()) {
            return assertion.getSubject().getNameID().getValue();
        }
        return null;
    }
    
    public static Properties loadProperties() throws IOException {
        Properties p = new Properties();
        p.load(SamlUtils.class.getResourceAsStream("/config.properties"));
        
        return p;
    }

}
