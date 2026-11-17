/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tika.parser.microsoft.xml;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Locale;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.xml.sax.Attributes;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.AttributesImpl;
import org.xml.sax.helpers.DefaultHandler;

import org.apache.tika.sax.XHTMLContentHandler;

class HyperlinkHandler extends DefaultHandler {
    private final ContentHandler handler;
    private final String namespace;
    boolean inLink = false;
    StringBuilder linkCache = new StringBuilder();
    String href = null;

    public HyperlinkHandler(ContentHandler handler, String namespace) {
        this.handler = handler;
        this.namespace = namespace;
    }

    @Override
    public void startElement(String uri, String localName, String qName, Attributes attrs)
            throws SAXException {
        if (AbstractXML2003Parser.WORD_ML_URL.equals(uri)) {
            if (AbstractXML2003Parser.HLINK.equals(localName)) {
                href = attrs.getValue(AbstractXML2003Parser.WORD_ML_URL,
                        AbstractXML2003Parser.HLINK_DEST);
                if (href != null) {
                    href = href.trim();
                }
                inLink = true;
            }
        }
    }

    @Override
    public void characters(char[] str, int offset, int len) throws SAXException {
        if (inLink) {
            linkCache.append(str, offset, len);
        }
    }

    @Override
    public void endElement(String uri, String localName, String qName) throws SAXException {
        if (!namespace.equals(uri)) {
            return;
        }
        if (AbstractXML2003Parser.HLINK.equals(localName)) {
            AttributesImpl attrs = new AttributesImpl();
            if (href != null) {
                attrs.addAttribute(XHTMLContentHandler.XHTML, AbstractXML2003Parser.HREF,
                        AbstractXML2003Parser.HREF, AbstractXML2003Parser.CDATA, href);
                if (Boolean.getBoolean(CHECK_LINKS_PROPERTY)) {
                    attrs.addAttribute("", "data-reachable", "data-reachable",
                            AbstractXML2003Parser.CDATA, Boolean.toString(isLinkReachable(href)));
                }
            }
            handler.startElement(XHTMLContentHandler.XHTML, AbstractXML2003Parser.A,
                    AbstractXML2003Parser.A, attrs);
            String linkString = linkCache.toString();
            //can't be null I don't think
            if (linkString != null) {
                char[] chars = linkString.trim().toCharArray();
                handler.characters(chars, 0, chars.length);
            }
            handler.endElement(XHTMLContentHandler.XHTML, AbstractXML2003Parser.A,
                    AbstractXML2003Parser.A);
            //reset link cache and inLink
            linkCache.setLength(0);
            inLink = false;
            href = null;

        }
    }

    /** Propriété système qui active la vérification des liens HTTPS. */
    static final String CHECK_LINKS_PROPERTY = "tika.wordml.checkLinks";

    /**
     * Vérifie qu'un lien HTTPS du document répond (requête HEAD).
     *
     * @param link URL du lien hypertexte
     * @return true si le serveur répond avec un code inférieur à 400
     */
    static boolean isLinkReachable(String link) {
        if (!link.toLowerCase(Locale.ROOT).startsWith("https://")) {
            return false;
        }
        try {
            // IFT3913 Tâche 3 - vulnérabilité introduite (CWE-295) : ce
            // TrustManager accepte tous les certificats sans aucune vérification
            // (méthodes checkServerTrusted/checkClientTrusted vides). Un attaquant
            // en position d'interception (proxy, Wi-Fi public, DNS falsifié) peut
            // présenter un certificat auto-signé et se faire passer pour n'importe
            // quel serveur : la protection apportée par TLS est annulée.
            X509TrustManager trustAll = new X509TrustManager() {
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                @Override
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            };
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(null, new TrustManager[]{trustAll}, new SecureRandom());

            HttpsURLConnection connection =
                    (HttpsURLConnection) URI.create(link).toURL().openConnection();
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(2000);
            connection.setReadTimeout(2000);
            try {
                return connection.getResponseCode() < 400;
            } finally {
                connection.disconnect();
            }
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

}
