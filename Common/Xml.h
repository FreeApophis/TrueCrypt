char *XmlNextNode (char *xmlNode);
char *XmlFindElement (char *xmlNode, char *nodeName);
char *XmlGetAttributeText (char *xmlNode, char *xmlAttrName, char *xmlAttrValue, int xmlAttrValueSize);
char *XmlGetNodeText (char *xmlNode, char *xmlText, int xmlTextSize);
int XmlWriteHeader (FILE *file);
int XmlWriteFooter (FILE *file);
char *XmlFindElementByAttributeValue (char *xml, char *nodeName, char *attrName, char *attrValue);
char *XmlQuoteText (char *textSrc, char *textDst, int textDstMaxSize);
