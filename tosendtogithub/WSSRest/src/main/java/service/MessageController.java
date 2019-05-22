package service;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.activation.DataHandler;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Properties;
import com.sun.nio.sctp.HandlerResult;

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.Merlin;
/*import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerResult;*/
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Properties;

@RestController
public class MessageController {

    private static final Logger LOG = LoggerFactory.getLogger(MessageFactory.class);


    @RequestMapping(value = "/message", method = RequestMethod.POST)
    @ResponseBody
    public Message getContent(@RequestParam(value="content") String contentVal) throws Exception {
        Document doc = convertStringToDocument(contentVal);
        LOG.info("document :: "+doc.getXmlStandalone());
/*try {
    processSoapSecurityHeader(contentVal,"D:\\workspaces\\WSSRest\\src\\main\\resources\\keystore.jks","demo123","ws-security-spring-boot-cxf");

}catch (Exception e){
    LOG.info(e.getMessage());
}*/


            InputStream is = new ByteArrayInputStream(contentVal.getBytes());
            SOAPMessage message = MessageFactory.newInstance().createMessage(null, is);

            SOAPPart soapPart = message.getSOAPPart();
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = dbFactory.newDocumentBuilder();
            Document document = builder.parse("D:\\workspaces\\WSSRest\\src\\main\\resources\\soap.xml");
            DOMSource domSource = new DOMSource(document);
            soapPart.setContent(domSource);

            //File mf=new File("soap.xml");

            URL url = new URL("https://o7planning.org/fr/11647/exemple-spring-boot-restful-client-avec-resttemplate#a13901622");
            DataHandler handler = new DataHandler(url);
            AttachmentPart attachPart = message.createAttachmentPart(handler);
            message.addAttachmentPart(attachPart);
        //Verify XML document is build correctly
        LOG.info("document 2 :: "+doc.getFirstChild().getNodeName());
        LOG.info("",message.getSOAPBody());
        LOG.info("",message.getSOAPPart());
        LOG.info("",message.getSOAPHeader());
        return new Message(message.getSOAPBody().toString());


    }

    @RequestMapping(value = "/message", method = RequestMethod.GET)
    @ResponseBody
    public String getMessage() {
        return "OK";
    }

    private static String convertDocumentToString(org.w3c.dom.Document doc) {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer;
        try {
            transformer = tf.newTransformer();
            // below code to remove XML declaration
            // transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));
            String output = writer.getBuffer().toString();
            return output;
        } catch (TransformerException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static org.w3c.dom.Document convertStringToDocument(String xmlStr) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder;
        try
        {
            builder = factory.newDocumentBuilder();
            Document doc = builder.parse( new InputSource( new StringReader( xmlStr ) ) );
            return doc;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void processSoapSecurityHeader(String soapRequest, String keyStore, String keyStorePwd, String alias) throws Exception {
//create a soapmessage from the requestxml
        SOAPMessage soapMessage = MessageFactory.newInstance().createMessage(null, new ByteArrayInputStream(soapRequest.getBytes()));
        //import the keystore
        FileInputStream is = new FileInputStream(keyStore);
        KeyPair keypair = null;

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, keyStorePwd.toCharArray());
        Certificate cert = null;
        Key key = keystore.getKey(alias, keyStorePwd.toCharArray());
        if (key instanceof PrivateKey) {
            cert = keystore.getCertificate(alias);
            PublicKey publicKey = cert.getPublicKey();
            keypair = new KeyPair(publicKey, (PrivateKey) key);
        }
        Properties properties = new Properties();
        properties.setProperty("org.apache.ws.security.crypto.provider", "org.apache.ws.security.components.crypto.Merlin");
        Crypto crypto = CryptoFactory.getInstance(properties);
        keystore.setKeyEntry(alias, keypair.getPrivate(), keyStorePwd.toCharArray(), new Certificate[]{cert});
        ((Merlin) crypto).setKeyStore(keystore);
        crypto.loadCertificate(new ByteArrayInputStream(cert.getEncoded()));
        WSSecurityEngine engine = new WSSecurityEngine();
        /*WSSConfig config = WSSConfig.getNewInstance();
        config.setWsiBSPCompliant(false);
        engine.setWssConfig(config);*/
        toDocumentFile(soapMessage);
        //List<WSSecurityEngineResult> rest = engine.processSecurityHeader();

        List<WSSecurityEngineResult> handlerRes =  engine.processSecurityHeader(toDocument(soapMessage), null, null, crypto);


        for (WSSecurityEngineResult WSecList : handlerRes) {
            //Voir les elements du WSSecurityEngineResult
            LOG.info("Details of security header after validation {}" , WSecList.toString());
            File file = new File("Detailsofsecurityheadervalidation");
            FileWriter fileWriter = new FileWriter(file);
            fileWriter.write(WSecList.toString());
            fileWriter.flush();
            fileWriter.close();

        }
        LOG.info("Validation code executed");




    }


    public Document toDocument(SOAPMessage soapMsg)
            throws TransformerConfigurationException, TransformerException, SOAPException, IOException {
        Source src = soapMsg.getSOAPPart().getContent();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        DOMResult result = new DOMResult();
        transformer.transform(src, result);
        return (Document)result.getNode();
    }
    public Document toDocumentFile(SOAPMessage soapMsg)
            throws TransformerConfigurationException, TransformerException, SOAPException, IOException {
        Source src = soapMsg.getSOAPPart().getContent();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        DOMResult result = new DOMResult();
        transformer.transform(src, result);
        Source source=new DOMSource((Document)result.getNode());
        TransformerFactory tranFactory = TransformerFactory.newInstance();
        Transformer aTransformer = tranFactory.newTransformer();
        Result dest = new StreamResult(new File("xmlFileName.xml"));
        aTransformer.transform(source, dest);
        return (Document)result.getNode();
    }
}
