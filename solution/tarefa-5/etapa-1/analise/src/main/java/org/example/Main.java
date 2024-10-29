package org.example;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class Main {

    public static void main(String[] args) {
        //Feito com base em: https://stackoverflow.com/questions/4076910/how-to-retrieve-element-value-of-xml-using-java
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();

            Document document = builder.parse("src/main/resources/LU.xml");
            document.getDocumentElement().normalize();

            NodeList serviceList = document.getElementsByTagName("TSPService");

            for (int i = 0; i < serviceList.getLength(); i++) {
                Node serviceNode = serviceList.item(i);

                if (serviceNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element serviceElement = (Element) serviceNode;

                    String serviceTypeIdentifier = serviceElement
                            .getElementsByTagName("ServiceTypeIdentifier")
                            .item(0)
                            .getTextContent();

                    String serviceName = serviceElement
                            .getElementsByTagName("ServiceName")
                            .item(0)
                            .getTextContent();

                    System.out.println(serviceTypeIdentifier + ": " + serviceName);
                }
            }

        } catch (Exception e) {
            System.out.println("ERRO: " + e);
        }
    }
}
