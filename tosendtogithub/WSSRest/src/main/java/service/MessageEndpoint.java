package service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ws.server.endpoint.annotation.Endpoint;
import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;


@Endpoint
public class MessageEndpoint {
    private static final String NAMESPACE_URI = "http://localhost/messageEndpoint";


    @Autowired
    public MessageEndpoint() {

    }

    @PayloadRoot(namespace = NAMESPACE_URI, localPart = "getContent")
    @ResponsePayload
    public String getContentSoap(@RequestPayload String request) {
        return request;
    }

}