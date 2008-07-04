/*
 Copyright (c) 2005 TrueCrypt Foundation. All rights reserved.

 Governed by the TrueCrypt License 2.5 the full text of which is contained
 in the file License.txt included in TrueCrypt binary and source code
 distribution packages.
*/

#ifdef __cplusplus
extern "C" {
#endif

char *XmlNextNode (char *xmlNode);
char *XmlFindElement (char *xmlNode, char *nodeName);
char *XmlGetAttributeText (char *xmlNode, char *xmlAttrName, char *xmlAttrValue, int xmlAttrValueSize);
char *XmlGetNodeText (char *xmlNode, char *xmlText, int xmlTextSize);
int XmlWriteHeader (FILE *file);
int XmlWriteFooter (FILE *file);
char *XmlFindElementByAttributeValue (char *xml, char *nodeName, char *attrName, char *attrValue);
char *XmlQuoteText (char *textSrc, char *textDst, int textDstMaxSize);

#ifdef __cplusplus
}
#endif
