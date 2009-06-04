#include "config_control.h"
#include <stdio.h>
#include <string.h>
#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>
#include <libxml2/libxml/xmlstring.h>
#include <sys/socket.h>

static void get_element(xmlNode * a_node);


void
init_config(void)
{
    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;

    /*
     * this initialize the library and check potential ABI mismatches
     * between the version it was compiled for and the actual shared
     * library used.
     */
    LIBXML_TEST_VERSION

    /*parse the file and get the DOM */
    doc = xmlReadFile(CONF_PATH, NULL, 0);

    if (doc == NULL)
      {
        puts("Could not parse or find file. A sample file will be generated "
            "automatically. Try 'gedit /etc/ruijie.conf'");
        generate_conf();
      }

    /*Get the root element node */
    root_element = xmlDocGetRootElement(doc);

    get_element(root_element);

    /*free the document */
    xmlFreeDoc(doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    if ((m_name == NULL) || (m_name[0] == 0))
    g_error("invalid name found in ruijie.conf!\n");
    if ((m_password == NULL) || (m_password[0] == 0))
    g_error("invalid password found in ruijie.conf!\n");
    if ((m_authenticationMode < 0) || (m_authenticationMode> 1))
    g_error("invalid authenticationMode found in ruijie.conf!\n");
    if ((m_nic == NULL) || (strcmp(m_nic, "") == 0)
        || (strcmp(m_nic, "any") == 0))
    g_error("invalid nic found in ruijie.conf!\n");
    if ((m_echoInterval < 0) || (m_echoInterval> 100))
    g_error("invalid echo interval found in ruijie.conf!\n");
    //if ((m_intelligentReconnect < 0) || (m_intelligentReconnect> 1))
    if ((m_intelligentReconnect < 0))
    g_error("invalid intelligentReconnect found in ruijie.conf!\n");


    //just set them to zero since they don't seem to be important.
    memset(m_netgate, 0, sizeof(m_netgate));
    memset(m_dns1, 0, sizeof(m_dns1));
}

void
generate_conf(void)
{

    xmlDocPtr doc = NULL; /* document pointer */

    xmlNodePtr root_node = NULL, account_node = NULL,
    setting_node = NULL, msg_node = NULL;/* node pointers */

    int rc;

    // Creates a new document, a node and set it as a root node

    doc = xmlNewDoc(BAD_CAST "1.0");

    root_node = xmlNewNode(NULL, BAD_CAST CONF_NAME);
    xmlNewProp(root_node, BAD_CAST "version", BAD_CAST C_VERSION);
    xmlAddChild(root_node, xmlNewComment((xmlChar *)
            "This is a sample configuration file of RuijieClient, "
            "change it appropriately according to your settings."));

    xmlDocSetRootElement(doc, root_node);

    //creates a new node, which is "attached" as child node of root_node node.
    account_node = xmlNewChild(root_node, NULL, BAD_CAST "account", NULL);
    xmlNewChild(account_node, NULL, BAD_CAST "Name", BAD_CAST "");
    xmlNewChild(account_node, NULL, BAD_CAST "Password", BAD_CAST "");

    setting_node = xmlNewChild(root_node, NULL, BAD_CAST "settings", NULL);
    xmlAddChild(setting_node, xmlNewComment((xmlChar *) "0: Standard, 1: Private"));
    xmlNewChild(setting_node, NULL, BAD_CAST "AuthenticationMode", BAD_CAST "1");
    xmlNewChild(setting_node, NULL, BAD_CAST "NIC", BAD_CAST "eth0");
    xmlNewChild(setting_node, NULL, BAD_CAST "EchoInterval", BAD_CAST "25");
    xmlAddChild(setting_node, xmlNewComment((xmlChar *) "IntelligentReconnect: "
        "0: Disable IntelligentReconnect, 1: Enable IntelligentReconnect, >10:Focus Reconnect Aftre seconds"));
    xmlNewChild(setting_node, NULL, BAD_CAST "IntelligentReconnect", BAD_CAST "1");
    xmlAddChild(setting_node, xmlNewComment((xmlChar *) "AutoConnect: "
        "0: Disable AutoConnect, 1: Enable AutoConnect "));
    xmlNewChild(setting_node, NULL, BAD_CAST "AutoConnect", BAD_CAST "0");
    xmlAddChild(setting_node, xmlNewComment((xmlChar *) "Fake Version for cheating server"));
    xmlNewChild(setting_node, NULL, BAD_CAST "FakeVersion", BAD_CAST "3.99");
    xmlAddChild(setting_node, xmlNewComment((xmlChar *) "Fake IP for cheating server"));
    xmlNewChild(setting_node, NULL, BAD_CAST "FakeAddress", BAD_CAST "");
    xmlAddChild(setting_node, xmlNewComment((xmlChar *) "DHCP mode 0: Disable, "
        "1: Enable DHCP before authentication, 2: Enable DHCP after authentication "));
    xmlNewChild(setting_node, NULL, BAD_CAST "DHCPmode", BAD_CAST "0");

    //Dumping document to stdio or file
    rc = xmlSaveFormatFileEnc(CONF_PATH, doc, "UTF-8", 1);

    if (rc == -1)
      g_error("Configuration file fail in generating.");

    /*free the document */
    xmlFreeDoc(doc);
    xmlCleanupParser();

    xmlMemoryDump(); // debug memory for regression tests

    puts("Configuration file has been generated.");
    exit(0);
}
static void
get_element(xmlNode * a_node)
{
    xmlNode *cur_node = NULL;
    char *node_content, *node_name;
    int i, len;

    for (cur_node = a_node; cur_node != NULL; cur_node = cur_node->next)
      {
        node_content = (char *)xmlNodeGetContent(cur_node);
        node_name = (char *)(cur_node->name);
        if (cur_node->type == XML_ELEMENT_NODE &&
            strcmp(node_content, "") &&
            node_name != NULL
            )
          {
            if (strcmp(node_name, "Name") == 0)
              {
                strncpy(name, node_content, sizeof(name) - 1);
                name[sizeof(name) - 1] = 0;
                m_name = name;
              }
            else if (strcmp(node_name, "Password") == 0)
              {
                strncpy(password, node_content, sizeof(password) - 1);
                password[sizeof(password) - 1] = 0;
                m_password = password;
              }
            else if (strcmp(node_name, "AuthenticationMode") == 0)
              {
                m_authenticationMode = atoi(node_content);
              }
            else if (strcmp(node_name, "NIC") == 0)
              {
                for (i = 0; i < strlen(node_content); i++)
                  node_content[i] = tolower(node_content[i]);
                strncpy(nic, node_content, sizeof(nic) - 1);
                nic[sizeof(nic) - 1] = 0;
                m_nic = nic;
              }
            else if (strcmp(node_name, "EchoInterval") == 0)
              {
                m_echoInterval = atoi(node_content);
              }
            else if (strcmp(node_name, "IntelligentReconnect") == 0)
              {
                m_intelligentReconnect = atoi(node_content);
              }
            else if (strcmp(node_name, "FakeVersion") == 0)
              {
                strncpy(fakeVersion, node_content, sizeof(fakeVersion) - 1);
                fakeVersion[sizeof(fakeVersion) - 1] = 0;
                m_fakeVersion = fakeVersion;
              }
            else if (strcmp(node_name, "DHCPmode") == 0)
              {
                m_dhcpmode = atoi(node_content);
              }
             /* comment out for further useage
            else if (strcmp(node_name, "FakeMAC") == 0)
              {
                strncpy(fakeMAC, node_content, sizeof(fakeMAC) - 1);
                fakeMAC[sizeof(fakeMAC) - 1] = 0;
                m_fakeMAC = fakeMAC;
              }
              */
            else if (strcmp(node_name, "FakeAddress") == 0)
              {
                strncpy(fakeAddress, node_content, sizeof(fakeAddress) - 1);
                fakeAddress[sizeof(fakeAddress) - 1] = 0;
                if (inet_pton(AF_INET, fakeAddress, m_ip) <= 0)
                g_warning("invalid fakeAddress found in ruijie.conf, ignored...\n");
                else
                m_fakeAddress = fakeAddress;
              }
          }

        get_element(cur_node->children);
      }
}
