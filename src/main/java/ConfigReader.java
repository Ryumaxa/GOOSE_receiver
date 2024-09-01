import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;

public class ConfigReader {
    public static Config readConfig(String filePath) {
        Config config = new Config();

        try {
            File file = new File(filePath);
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(file);
            doc.getDocumentElement().normalize();

            config.setNetworkInterface(getElementValue(doc, "networkInterface"));
            config.setSource(getElementValue(doc, "source"));

        } catch (Exception e) {
            e.printStackTrace();
        }

        return config;
    }

    private static String getElementValue(Document doc, String tagName) {
        NodeList nodeList = doc.getElementsByTagName(tagName);
        Node node = nodeList.item(0);
        if (node != null && node.getNodeType() == Node.ELEMENT_NODE) {
            return node.getTextContent();
        }
        return null;
    }
}
