/*
 * This program is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License, version 2.1 as published by the Free Software
 * Foundation.
 *
 * You should have received a copy of the GNU Lesser General Public License along with this
 * program; if not, you can obtain a copy at http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html
 * or from the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * Copyright (c) 2016 - 2017 Hitachi Vantara.  All rights reserved.
 */
package org.pentaho.metadata.util;

import org.junit.Assert;
import org.junit.Test;
import org.pentaho.metadata.model.Domain;
import org.pentaho.pms.core.exception.PentahoMetadataException;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.StringWriter;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class XmiParserTest {
  /**
   * @see <a href="https://en.wikipedia.org/wiki/Billion_laughs" />
   */
  private static final String MALICIOUS_XML =
    "<?xml version=\"1.0\"?>\n"
      + "<!DOCTYPE lolz [\n"
      + " <!ENTITY lol \"lol\">\n"
      + " <!ELEMENT lolz (#PCDATA)>\n"
      + " <!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n"
      + " <!ENTITY lol2 \"&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;\">\n"
      + " <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n"
      + " <!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">\n"
      + " <!ENTITY lol5 \"&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;\">\n"
      + " <!ENTITY lol6 \"&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;\">\n"
      + " <!ENTITY lol7 \"&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;\">\n"
      + " <!ENTITY lol8 \"&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;\">\n"
      + " <!ENTITY lol9 \"&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;\">\n"
      + "]>\n"
      + "<lolz>&lol9;</lolz>";

  private static final String XXE_XML =
          "<?xml version=\"1.0\"?>\n"
                  + "<!DOCTYPE foo\n"
                  + " [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]>\n" // linux centric, can use local file
                  + " <search><user>&xxe;</user></search>\n";

  private static final String Xinclude_GENERIC_XML =
          "<?xml version=\"1.0\"?>\n"
                  + "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\">\n"
                  + "<xi:include parse=\"text\" href=\"file:///etc/passwd\"/>\n" //linux centric, can use local file
                  + "</foo>\n";

  private static final String DOMAIN_XML =
          "<?xml version=\"1.0\"?>\n"
                  + "<XMI xmlns:xi=\"http://www.w3.org/2001/XInclude\" xmlns:CWMMDB=\"org.omg.xmi.namespace.CWMMDB\" xmlns:CWMTFM=\"org.omg.xmi.namespace.CWMTFM\" xmlns:CWMRDB=\"org.omg.xmi.namespace.CWMRDB\" xmlns:CWM=\"org.omg.xmi.namespace.CWM\" xmlns:CWMOLAP=\"org.omg.xmi.namespace.CWMOLAP\" timestamp=\"Fri May 13 14:56:16 EDT 2022\" xmi.version=\"1.2\">\n"
                  + "<XMI.content>\n"
                  + "<CWM:Parameter name=\"en_US\" xmi.id=\"a1\"><CWM:ModelElement.taggedValue><CWM:TaggedValue tag=\"LOCALE_IS_DEFAULT\" value=\"Y\" xmi.id=\"a2\"/><CWM:TaggedValue tag=\"LOCALE_ORDER\" value=\"1\" xmi.id=\"a3\"/><CWM:TaggedValue tag=\"LOCALE_DESCRIPTION\" value=\"English (US)\" xmi.id=\"a4\"/></CWM:ModelElement.taggedValue></CWM:Parameter>\n"
                  + "</XMI.content>\n"
                  + "</XMI>\n";

  // if Xinclude works, same as above #DOMAIN_XML_ORIG
  private static final String Xinclude_DOMAIN_XML =
          "<?xml version=\"1.0\"?>\n"
                  + "<XMI xmlns:xi=\"http://www.w3.org/2001/XInclude\" xmlns:CWMMDB=\"org.omg.xmi.namespace.CWMMDB\" xmlns:CWMTFM=\"org.omg.xmi.namespace.CWMTFM\" xmlns:CWMRDB=\"org.omg.xmi.namespace.CWMRDB\" xmlns:CWM=\"org.omg.xmi.namespace.CWM\" xmlns:CWMOLAP=\"org.omg.xmi.namespace.CWMOLAP\" timestamp=\"Fri May 13 14:56:16 EDT 2022\" xmi.version=\"1.2\">\n"
                  + "<XMI.content>\n"
                  + "<xi:include parse=\"text\" href=\"file://" +  getParametersFileName() + "\"/>\n"
                  + "</XMI.content>\n"
                  + "</XMI>\n";


  @Test
  public void secureFeatureEnabled_AfterDocBuilderFactoryCreation() throws Exception {
    DocumentBuilderFactory documentBuilderFactory = XmiParser.createSecureDocBuilderFactory();
    boolean secureFeatureEnabled = documentBuilderFactory.getFeature( XMLConstants.FEATURE_SECURE_PROCESSING );

    assertEquals( true, secureFeatureEnabled );
  }

  @Test( expected = PentahoMetadataException.class )
  public void exceptionThrown_WhenParsingXmlWith_BigNumberOfExternalEntities() throws Exception {
    XmiParser xmiParser = new XmiParser();
    xmiParser.parseXmi( new ByteArrayInputStream( MALICIOUS_XML.getBytes() ) );
  }

  // SPIKE: render external entity from external filesystem

  @Test( expected = PentahoMetadataException.class )
  public void spike_WhenXmiParserParsingXmlWith_ExternalEntities_exceptionThrown() throws Exception {
    XmiParser xmiParser = new XmiParser();
    xmiParser.parseXmi( new ByteArrayInputStream( XXE_XML.getBytes() ) );
  }

  // SPIKE: Xinclude for <xi:include

  @Test
  public void spike_WhenGenericParsing_enabledXinclude_Pass() throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setXIncludeAware( true ); dbf.setNamespaceAware( true ); // enable Xinclude
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse( new InputSource(  new ByteArrayInputStream( Xinclude_GENERIC_XML.getBytes() )  ) );
    String strDoc = toString(doc);
    Assert.assertTrue(strDoc.contains("root:")); // all systems should have root user
  }

  @Test
  public void spike_WhenGenericParsing_disabledXinclude_Fail() throws Exception {
    DocumentBuilderFactory dbf = XmiParser.createSecureDocBuilderFactory();
    //dbf.setXIncludeAware( true ); dbf.setNamespaceAware( true ); // enable Xinclude
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse( new InputSource(  new ByteArrayInputStream( Xinclude_GENERIC_XML.getBytes() )  ) );
    String strDoc = toString(doc);
    /**
     * assertion will fail
     * // will fail, doesn't substitute text, just has text like:
     * <xi:include parse="text" href="file:///etc/passwd"/>
     */
    Assert.assertFalse(strDoc.contains("root:")); // all systems should have root user
  }

  @Test
  public void spike_WhenXmiParserParsingXmlWith_domainfile_Pass() throws Exception {
    XmiParser xmiParser = new XmiParser();
    Domain domain = xmiParser.parseXmi( new ByteArrayInputStream( DOMAIN_XML.getBytes() ) );
    assertNotNull(domain);
    assertNotNull(domain.getLocales());
    assertEquals(1, domain.getLocales().size());
  }

  @Test
  public void spike_WhenGenericParsing_enabledXinclude_fileXinclude_Pass() throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setXIncludeAware( true ); dbf.setNamespaceAware( true ); // enable Xinclude
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse( new InputSource(  new ByteArrayInputStream( Xinclude_DOMAIN_XML.getBytes() )  ) );
    String strDoc = toString(doc);
    Assert.assertTrue(strDoc.contains("LOCALE_DESCRIPTION")); // verifying the xinclude works
  }

  @Test
  public void spike_WhenXmiParserParsingXmlWith_fileXinclude_Fail() throws Exception {
    XmiParser xmiParser = new XmiParser();
    Domain domain = xmiParser.parseXmi( new ByteArrayInputStream( Xinclude_DOMAIN_XML.getBytes() ) );
    assertNotNull(domain);
    assertNotNull(domain.getLocales());
    assertEquals(0, domain.getLocales().size()); // yeah! didn't find any locale, so xinclude didn't work
  }

  /**
   * get asbolute fila path to domain snippet file
   * @return
   */
  public static String getParametersFileName(){
    String path = "src/test/resources/domainParameters.txt";
    File file = new File(path);
    return file.getAbsolutePath();
  }

  /**
   * helper function
   * @param doc
   * @return
   */
  public static String toString(Document doc) {
    try {
      StringWriter sw = new StringWriter();
      TransformerFactory tf = TransformerFactory.newInstance();
      Transformer transformer = tf.newTransformer();
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
      transformer.setOutputProperty(OutputKeys.METHOD, "xml");
      transformer.setOutputProperty(OutputKeys.INDENT, "yes");
      transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

      transformer.transform(new DOMSource(doc), new StreamResult(sw));
      return sw.toString();
    } catch (Exception ex) {
      throw new RuntimeException("Error converting to String", ex);
    }
  }

}
