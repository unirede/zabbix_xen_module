/*
 ** Xen Module for Zabbix - Unirede
 ** Copyright (C) 2001-2015 Zabbix SIA
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation; either version 2 of the License, or
 ** (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **/

/* Zabbix Includes */
#include "sysinc.h"
#include "module.h"
#include "sysinfo.h"
#include "log.h"
#include "zbxjson.h"

/* Aditional Includes */
#include "xen/api/xen_all.h"
#include "curl.h"
#include <libxml/parser.h>

typedef struct
{
    xen_result_func func;
    void *handle;
} xen_comms;

typedef struct
{
    char    *data;
    size_t  alloc;
    size_t  offset;
} ZBX_HTTPPAGE;

/* the variable keeps timeout setting for item processing */
static int    item_timeout = 10;
static xen_session *session;
static char *url;
static ZBX_HTTPPAGE page;

static int  xen_module_version(AGENT_REQUEST *request, AGENT_RESULT *result);

/* Host functions */
static int  xen_host_storage_discovery(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_host_network_discovery(AGENT_REQUEST *request, AGENT_RESULT *result);

static int  xen_host_cpu_avg(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_host_cpu_usage(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_host_loadavg(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_host_network_in(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_host_network_out(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_host_memory_total(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_host_memory_free(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_host_xapi_memory_usage(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_host_xapi_memory_free(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_host_xapi_memory_live(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_host_xapi_memory_allocation(AGENT_REQUEST *request, AGENT_RESULT *result);

static int  xen_host_sr_cache_size(AGENT_REQUEST *request, AGENT_RESULT *result); // function not in use
static int  xen_host_sr_cache_hits(AGENT_REQUEST *request, AGENT_RESULT *result); // function not in use
static int  xen_host_sr_cache_misses(AGENT_REQUEST *request, AGENT_RESULT *result); // function not in use

/* Datastore functions */
static int  xen_sr_virtual_allocation(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_sr_physical_utilisation(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_sr_physical_size(AGENT_REQUEST *request, AGENT_RESULT *result);

/* VM functions */
static int  xen_vm_discovery(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_vm_cpu_discovery(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_vm_disk_discovery(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_vm_network_discovery(AGENT_REQUEST *request, AGENT_RESULT *result);

static int  xen_vm_cpu_usage(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_vm_cpu_avg(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_vm_disk_read(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_vm_disk_write(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_vm_memory_total(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_vm_memory_target(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_vm_memory_free(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_vm_network_in(AGENT_REQUEST *request, AGENT_RESULT *result);
static int  xen_vm_network_out(AGENT_REQUEST *request, AGENT_RESULT *result);

static ZBX_METRIC keys[] =
/*      KEY                             FLAG                FUNCTION                    TEST PARAMETERS */
{
    {"xen.module.version",              0,                  xen_module_version,              NULL},

    {"xen.host.network.discovery",      CF_HAVEPARAMS,      xen_host_network_discovery,      NULL},
    {"xen.host.sr.discovery",           CF_HAVEPARAMS,      xen_host_storage_discovery,      NULL},
    {"xen.host.cpu.avg",                CF_HAVEPARAMS,      xen_host_cpu_avg,                NULL},
    {"xen.host.cpu.usage",              CF_HAVEPARAMS,      xen_host_cpu_usage,              NULL},
    {"xen.host.loadavg",                CF_HAVEPARAMS,      xen_host_loadavg,                NULL},
    {"xen.host.memory.total",           CF_HAVEPARAMS,      xen_host_memory_total,           NULL},
    {"xen.host.memory.free",            CF_HAVEPARAMS,      xen_host_memory_free,            NULL},
    {"xen.host.network.in",             CF_HAVEPARAMS,      xen_host_network_in,             NULL},
    {"xen.host.network.out",            CF_HAVEPARAMS,      xen_host_network_out,            NULL},
    {"xen.host.xapi.memory.allocation", CF_HAVEPARAMS,      xen_host_xapi_memory_allocation, NULL},
    {"xen.host.xapi.memory.free",       CF_HAVEPARAMS,      xen_host_xapi_memory_free,       NULL},
    {"xen.host.xapi.memory.live",       CF_HAVEPARAMS,      xen_host_xapi_memory_live,       NULL},
    {"xen.host.xapi.memory.usage",      CF_HAVEPARAMS,      xen_host_xapi_memory_usage,      NULL},

    {"xen.sr.virtual_allocation",       CF_HAVEPARAMS,      xen_sr_virtual_allocation,       NULL},
    {"xen.sr.physical_utilisation",     CF_HAVEPARAMS,      xen_sr_physical_utilisation,     NULL},
    {"xen.sr.physical_size",            CF_HAVEPARAMS,      xen_sr_physical_size,            NULL},

    {"xen.vm.discovery",                CF_HAVEPARAMS,      xen_vm_discovery,                NULL},
    {"xen.vm.cpu.discovery",            CF_HAVEPARAMS,      xen_vm_cpu_discovery,            NULL},
    {"xen.vm.disk.discovery",           CF_HAVEPARAMS,      xen_vm_disk_discovery,           NULL},
    {"xen.vm.network.discovery",        CF_HAVEPARAMS,      xen_vm_network_discovery,        NULL},
    {"xen.vm.cpu.usage",                CF_HAVEPARAMS,      xen_vm_cpu_usage,                NULL},
    {"xen.vm.disk.read",                CF_HAVEPARAMS,      xen_vm_disk_read,                NULL},
    {"xen.vm.disk.write",               CF_HAVEPARAMS,      xen_vm_disk_write,               NULL},
    {"xen.vm.memory.total",             CF_HAVEPARAMS,      xen_vm_memory_total,             NULL},
    {"xen.vm.memory.target",            CF_HAVEPARAMS,      xen_vm_memory_target,            NULL},
    {"xen.vm.memory.free",              CF_HAVEPARAMS,      xen_vm_memory_free,              NULL},
    {"xen.vm.network.in",               CF_HAVEPARAMS,      xen_vm_network_in,               NULL},
    {"xen.vm.network.out",              CF_HAVEPARAMS,      xen_vm_network_out,              NULL},

    {NULL}
};

/******************************************************************************
 *                                                                            *
 * Function: zbx_module_api_version                                           *
 *                                                                            *
 * Purpose: returns version number of the module interface                    *
 *                                                                            *
 * Return value: ZBX_MODULE_API_VERSION_ONE - the only version supported by   *
 *               Zabbix currently                                             *
 *                                                                            *
 ******************************************************************************/
int    zbx_module_api_version()
{
    return ZBX_MODULE_API_VERSION_ONE;
}

/******************************************************************************
 *                                                                            *
 * Function: zbx_module_item_timeout                                          *
 *                                                                            *
 * Purpose: set timeout value for processing of items                         *
 *                                                                            *
 * Parameters: timeout - timeout in seconds, 0 - no timeout set               *
 *                                                                            *
 ******************************************************************************/
void zbx_module_item_timeout(int timeout)
{
    item_timeout = timeout;
}

/******************************************************************************
 *                                                                            *
 * Function: zbx_module_item_list                                             *
 *                                                                            *
 * Purpose: returns list of item keys supported by the module                 *
 *                                                                            *
 * Return value: list of item keys                                            *
 *                                                                            *
 ******************************************************************************/
ZBX_METRIC    *zbx_module_item_list()
{
    return keys;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_module_version                                               *
 *                                                                            *
 * Purpose: returns version number of this module                             *
 *                                                                            *
 * Return value: the version of module                                        *
 *                                                                            *
 ******************************************************************************/
static int xen_module_version(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    SET_STR_RESULT(result, strdup("Version 0.7 - Unirede Soluções Corporativas"));
    return SYSINFO_RET_OK;
}

/******************************************************************************
 *                                                                            *
 * Function: sysinfo_ret_string                                               *
 *                                                                            *
 * Purpose: returns the string representation of ret                          *
 *                                                                            *
 ******************************************************************************/
static const char   *sysinfo_ret_string(int ret)
{
    switch (ret)
    {
        case SYSINFO_RET_OK:
            return "OK";
        case SYSINFO_RET_FAIL:
            return "FAIL";
        default:
            return "UNKNOWN";
    }
}

/******************************************************************************
 *                                                                            *
 * Function: get_element_values                                               *
 *                                                                            *
 * Purpose: get the value based on filter in a pointer to xml                 *
 *                                                                            *
 * Parameters: xmlNode - pointer to <ds> structure                            *
 *             filter - a string to search within name tag                    *
 *                                                                            *
 * Return value: the picked up value, or NULL if value was not found          *
 *                                                                            *
 * Comment: Structure of xmlNode in this point:                               *
 *          <name>memory_free_kib</name>                                      *
 *          <type>GAUGE</type>                                                *
 *          <minimal_heartbeat>300.0000</minimal_heartbeat>                   *
 *          <min>0.0</min>                                                    *
 *          <max>Infinity</max>                                               *
 *          <last_ds>8311460</last_ds>                                        *
 *          <value>23708689.0154</value>                                      *
 *          <unknown_sec>0</unknown_sec>                                      *
 *                                                                            *
 ******************************************************************************/
static char *get_element_values(xmlNode *a_node, char *filter)
{
    xmlNode *cur_node = NULL;
    xmlNode *val_node = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (strcmp(cur_node->name, "name") != 0) continue;
        if (strcmp(cur_node->children->content, filter) != 0) continue;
        val_node = cur_node->next;
        val_node = val_node->next;
        val_node = val_node->next;
        val_node = val_node->next;
        val_node = val_node->next;
        // val_node = val_node->next; //
        // val_node = val_node->next->next->next->next->next;

        return val_node->children->content;
    }
    return NULL;
}

/******************************************************************************
 *                                                                            *
 * Function: search_element_value                                             *
 *                                                                            *
 * Purpose: search for filter on xmlNode                                      *
 *                                                                            *
 * Parameters: xmlNode - pointer for one piece of the tree                    *
 *             filter - a string to search within name tag                    *
 *                                                                            *
 * Return value: tmp - the value found or NULL if this value was not found    *
 *                                                                            *
 * Comment: Structure of xmlNode in this point:                               *
 *            <rrd>                                                           *
 *                <version>0003</version>                                     *
 *                <step>5</step>                                              *
 *                <lastupdate>1420026407</lastupdate>                         *
 *                <ds>                                                        *
 *                    <name>memory_total_kib</name>                           *
 *                    <type>GAUGE</type>                                      *
 *                    <minimal_heartbeat>300.0000</minimal_heartbeat>         *
 *                    <min>0.0</min>                                          *
 *                    <max>Infinity</max>                                     *
 *                    <last_ds>33549248</last_ds>                             *
 *                    <value>95700236.4845</value>                            *
 *                    <unknown_sec>0</unknown_sec>                            *
 *                </ds>                                                       *
 *                <ds>...</ds>                                                *
 *                <rra>...</rra>                                              *
 *            </rrd>                                                          *
 *                                                                            *
 *  TODO: Use XPath like "//rrd/ds[name='cpu0']/last_ds"                      *
 *                                                                            *
 ******************************************************************************/
static char *search_element_value(xmlNode *a_node, char *filter)
{
    xmlNode *cur_node = NULL;
    char *tmp = NULL;

    for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            if (strcmp(cur_node->name, "ds") == 0 && strcmp(cur_node->parent->name, "rrd") == 0) {
                tmp = get_element_values(cur_node->children, filter);
            }
        }

        if (tmp == NULL) tmp = search_element_value(cur_node->children, filter);
        else return tmp;
    }
    return tmp;
}

/******************************************************************************
 *                                                                            *
 * Function: write_func                                                       *
 *                                                                            *
 * Purpose: auxiliar function to write data to xen_comms structure            *
 *                                                                            *
 * Parameters: ptr - pointer to data                                          *
 *             size - size of data                                            *
 *             nmemb - number of "sizes" of data                              *
 *             comms - function and handle to allocate                        *
 *                                                                            *
 * Return value: The size of comms alloc                                      *
 *                                                                            *
 ******************************************************************************/
static size_t write_func(void *ptr, size_t size, size_t nmemb, xen_comms *comms)
{
    size_t n = size * nmemb;
    return comms->func(ptr, n, comms->handle) ? n : 0;
}

/******************************************************************************
 *                                                                            *
 * Function: call_func                                                        *
 *                                                                            *
 * Purpose: function used for all Xen Server API calls                        *
 *                                                                            *
 * Parameters: data - the value to POST                                       *
 *             len - the length of data                                       *
 *             user_handle - Normally NULL                                    *
 *             result_handle - handle to use for all session                  *
 *             result_func - function to be executed                          *
 *                           by lixenserver to parse result                   *
 *                                                                            *
 * Return value: The return code of HTTP Request                              *
 *                                                                            *
 * Comment: body, strlen(body), s->handle, buffer, &bufferAdd                 *
 *                                                                            *
 ******************************************************************************/
static int call_func(const void *data, size_t len, void *user_handle, void *result_handle, xen_result_func result_func)
{
    (void) user_handle;

    CURL *curl = curl_easy_init();
    if (!curl)
        return -1;

    xen_comms comms ={
        .func = result_func,
        .handle = result_handle
    };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &comms);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);

    CURLcode result = curl_easy_perform(curl);

    curl_easy_cleanup(curl);

    return result;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_login                                                        *
 *                                                                            *
 * Purpose: login on Xen Server API and return session                        *
 *                                                                            *
 * Parameters: request - structure that contains item key and parameters      *
 *              request->key - item key without parameters                    *
 *              request->nparam - number of parameters                        *
 *              request->timeout - processing should not take longer than     *
 *                                 this number of seconds                     *
 *              request->params[N-1] - pointers to item key parameters        *
 *                                                                            *
 * Return value: A xen_session structure or NULL if don't log in              *
 *                                                                            *
 * Comment: xen_session structure                                             *
 *              xen_call_func   call_func;                                    *
 *              void            *handle;                                      *
 *              const char      *session_id;                                  *
 *              bool            ok;                                           *
 *              char            **error_description;                          *
 *              int             error_description_count;                      *
 *              xen_api_version api_version;                                  *
 *                                                                            *
 * TODO: validate login better                                                *
 *                                                                            *
 ******************************************************************************/
static int xen_login(char *username, char *password)
{
    session = xen_session_login_with_password(call_func, NULL, username, password, xen_api_latest_version);

    if (session != NULL && session->ok)
        return 1;
    else
        return 0;
}

/******************************************************************************
 *                                                                            *
 * Function: get_xen_server_metric                                            *
 *                                                                            *
 * Purpose: Get the requested value from rrd API of Xen Server                *
 *                                                                            *
 * Comment: N/A                                                               *
 *                                                                            *
 * TODO: use the correct type of data in result                               *
 *                                                                            *
 ******************************************************************************/
int get_xen_server_metric(AGENT_REQUEST *request, char *key, char *type, char *params, AGENT_RESULT *result)
{
    const char              *__function_name = "get_xen_server_metric";
    char *return_value = NULL, *url_api = NULL;
    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;
    int ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    // char *host = get_rparam(request, 3);
    // char *url_api = zbx_dsprintf(NULL , "%s/host_rrd?session_id=%s&uuid=%s", get_rparam(request, 0), session->session_id, host);
    if (params == NULL)
        url_api = zbx_dsprintf(NULL , "%s/%s_rrd?session_id=%s", url, type, session->session_id);
    else
        url_api = zbx_dsprintf(NULL , "%s/%s_rrd?session_id=%s&%s", url, type, session->session_id, params);

    /*parse the file and get the DOM */
    doc = xmlReadFile(url_api, NULL, 0);

    zbx_free(url_api);

    if (doc == NULL) goto end;

    /*Get the root element node */
    root_element = xmlDocGetRootElement(doc);

    return_value = search_element_value(root_element, key);

    if (return_value == NULL) {
        SET_MSG_RESULT(result, strdup("Not supported by Zabbix Agent"));
        zabbix_log(LOG_LEVEL_ERR, "Fail: didn't find %s", key);
        ret = NOTSUPPORTED;
        goto end;
    }

    SET_STR_RESULT(result, strdup(return_value));
    ret = SYSINFO_RET_OK;
end:
    /*free the document */
    xmlFreeDoc(doc);

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: get_xen_host_metric                                              *
 *                                                                            *
 * Purpose: Get the requested value for host from rrd API of Xen Server       *
 *                                                                            *
 * Comment: N/A                                                               *
 *                                                                            *
 ******************************************************************************/
int get_xen_host_metric(AGENT_REQUEST *request, char *key, unsigned int nparam, AGENT_RESULT *result)
{
    const char              *__function_name = "get_xen_host_metric";
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (nparam > request->nparam)
    {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        ret = SYSINFO_RET_FAIL;
        goto end;
    }

    url = get_rparam(request, 0);
    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;

    ret = get_xen_server_metric(request, key, "host", NULL, result);
end:
    xen_session_logout(session);

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: get_xen_vm_metric                                                *
 *                                                                            *
 * Purpose: Get the requested value for vm from rrd API of Xen Server         *
 *                                                                            *
 * Comment: N/A                                                               *
 *                                                                            *
 * TODO: Merge functions get_xen_vm_metric and get_xen_host_metric            *
 *                                                                            *
 ******************************************************************************/
int get_xen_vm_metric(AGENT_REQUEST *request, char *key, unsigned int nparam, AGENT_RESULT *result)
{
    const char              *__function_name = "get_xen_vm_metric";
    int                     ret = SYSINFO_RET_FAIL;
    char                    *param = NULL, *uuid = NULL;
    enum xen_vm_power_state power_state;
    xen_vm                  vm;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (nparam > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    url = get_rparam(request, 0);
    uuid = get_rparam(request, 3);
    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;
    if (!xen_vm_get_by_uuid(session, &vm, uuid)) goto end;
    if (!xen_vm_get_power_state(session, &power_state, vm)) goto end;
    if (power_state != XEN_VM_POWER_STATE_RUNNING)
    {
        ret = SYSINFO_RET_OK;
        SET_STR_RESULT(result, zbx_strdup(NULL, "0"));
        goto end;
    }

    param = zbx_dsprintf(NULL , "uuid=%s", uuid);

    ret = get_xen_server_metric(request, key, "vm", param, result);

    zbx_free(param);
end:
    xen_vm_free(vm);
    xen_session_logout(session);
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_network_discovery                                       *
 *                                                                            *
 * Purpose: discover all interfaces of host                                   *
 *                                                                            *
 * Comment: N/A                                                               *
 *                                                                            *
 ******************************************************************************/
static int xen_host_network_discovery(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_network_discovery";
    char                    *device_name = NULL;
    int                     ret = SYSINFO_RET_FAIL;
    struct zbx_json         j;
    unsigned int            i;
    int64_t                 vlanid;
    xen_pif_set             *interfaces;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (3 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    url = get_rparam(request, 0);
    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;

    if (!xen_pif_get_all(session, &interfaces)) goto free; 

    zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
    zbx_json_addarray(&j, ZBX_PROTO_TAG_DATA);

    for (i = 0; i < interfaces->size; i++)
    {
        if (!xen_pif_get_vlan(session, &vlanid, interfaces->contents[i])) goto free; 
        if (vlanid != -1) continue;

        if (!xen_pif_get_device(session, &device_name, interfaces->contents[i])) goto free;
        zbx_json_addobject(&j, NULL);
        zbx_json_addstring(&j, "{#PIF.NAME}", device_name, ZBX_JSON_TYPE_STRING);
        zbx_json_close(&j);
    }

    zbx_json_close(&j);
    SET_STR_RESULT(result, zbx_strdup(NULL, j.buffer));
    ret = SYSINFO_RET_OK;

free:
    zbx_json_free(&j);
    xen_pif_set_free(interfaces);
    zbx_free(device_name);
    xen_session_logout(session);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);
    return ret;
}
/******************************************************************************
 *                                                                            *
 * Function: xen_host_storage_discovery                                       *
 *                                                                            *
 * Purpose: Discover all datastores of host                                   *
 *                                                                            *
 * Comment: N/A                                                               *
 *                                                                            *
 ******************************************************************************/
static int xen_host_storage_discovery(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_storage_discovery";
    unsigned int            ret = SYSINFO_RET_FAIL, sr_count;
    char                    *sr_id = NULL;
    struct zbx_json         j;
    xen_sr_set              *sr_list;
    xen_sr_record           *storage;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (3 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    url = get_rparam(request, 0);
    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;

    if (!xen_sr_get_all(session, &sr_list)) goto free;

    zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
    zbx_json_addarray(&j, ZBX_PROTO_TAG_DATA);

    for (sr_count = 0; sr_count < sr_list->size; sr_count++)
    {
        sr_id = (char *) sr_list->contents[sr_count];
        if (!xen_sr_get_record(session, &storage, sr_id)) continue;
        zbx_json_addobject(&j, NULL);
        zbx_json_addstring(&j, "{#SR.UUID}", storage->uuid, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, "{#SR.TYPE}", storage->type, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, "{#SR.NAME}", storage->name_label, ZBX_JSON_TYPE_STRING);
        zbx_json_close(&j);
    }

    zbx_json_close(&j);
    SET_STR_RESULT(result, zbx_strdup(NULL, j.buffer));

    ret = SYSINFO_RET_OK;
free:
    zbx_json_free(&j);
    xen_sr_set_free(sr_list);
    xen_sr_record_free(storage);
    xen_session_logout(session);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_vm_discovery                                                 *
 *                                                                            *
 * Purpose: discover of VMs                                                   *
 *                                                                            *
 * Comment: N/A                                                               *
 *                                                                            *
 ******************************************************************************/
static int xen_vm_discovery(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_vm_discovery";
    int                     ret = SYSINFO_RET_FAIL;
    struct zbx_json         j;
    unsigned int            i;
    xen_vm_record           *rec;
    xen_vm_set              *vm_set;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (3 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    url = get_rparam(request, 0);
    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;

    /* get all vm entries */
    if (!xen_vm_get_all(session, &vm_set)) goto free;

    zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
    zbx_json_addarray(&j, ZBX_PROTO_TAG_DATA);

    for (i = 0; i < vm_set->size; i++)
    {
        if (!xen_vm_get_record(session, &rec, vm_set->contents[i])) goto free;
        if (rec->is_a_template) continue;
        if (rec->is_control_domain) continue;
        zbx_json_addobject(&j, NULL);
        zbx_json_addstring(&j, "{#VM.UUID}", rec->uuid, ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, "{#VM.NAME}", rec->name_label, ZBX_JSON_TYPE_STRING);
        zbx_json_close(&j);
    }

    zbx_json_close(&j);
    SET_STR_RESULT(result, zbx_strdup(NULL, j.buffer));

    ret = SYSINFO_RET_OK;
free:
    zbx_json_free(&j);
    xen_vm_set_free(vm_set);
    xen_vm_record_free(rec);
    xen_session_logout(session);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_cpu_avg                                                 *
 *                                                                            *
 * Comment: Function not in use                                               *
 *                                                                            *
 ******************************************************************************/
static int xen_host_cpu_avg(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_cpu_avg";
    char                    *key = "cpu_avg";
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    ret = get_xen_host_metric(request, key, 3, result);

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_cpu_usage                                               *
 *                                                                            *
 * Comment: N/A                                                               *
 *                                                                            *
 ******************************************************************************/
static int xen_host_cpu_usage(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_cpu_usage";
    char                    *key;
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    key = (4 == request->nparam) ? zbx_dsprintf(NULL , "cpu%s", get_rparam(request, 3)) : zbx_strdup(NULL, "cpu_avg");

    ret = get_xen_host_metric(request, key, 3, result);

    zbx_free(key);

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_loadavg                                                *
 *                                                                            *
 ******************************************************************************/
static int xen_host_loadavg(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_loadavg";
    char                    *key = "loadavg";
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    ret = get_xen_host_metric(request, key, 3, result);

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_memory_free                                             *
 *                                                                            *
 ******************************************************************************/
static int xen_host_memory_free(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_memory_free";
    char                    *key = "memory_free_kib";
    int                     ret = SYSINFO_RET_FAIL;
    int64_t                 free;
    xen_host_metrics        metric;
    xen_host_set            *host;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (3 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    url = get_rparam(request, 0);
    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;

    // @OLD@ ret = get_xen_host_metric(request, key, NULL, result);
    if (!xen_host_get_all(session, &host)) goto free;

    // FIXME: Assume that has just one host with one metric. Works in almost all cases.
    // if (!xen_host_get_metrics(session, &metric, host->contents[0])) goto free;
    if (!xen_host_get_metrics(session, &metric, host->contents[0])) goto free;

    if (xen_host_metrics_get_memory_free(session, &free, metric)) ret = SYSINFO_RET_OK;

    SET_UI64_RESULT(result, free);
free:
    xen_host_metrics_free(metric);
    xen_host_set_free(host);
    xen_session_logout(session);

end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_memory_total                                            *
 *                                                                            *
 ******************************************************************************/
static int xen_host_memory_total(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_memory_total";
    char                    *key = "memory_total_kib";
    int64_t                 total;
    xen_host_set            *host;
    xen_host_metrics        metric;
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (3 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    url = get_rparam(request, 0);
    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;

    // @@OLD@@ ret = get_xen_host_metric(request, key, NULL, result);

    if (!xen_host_get_all(session, &host)) goto free;

    // FIXME: Assume that has just one host with one metric. Works in almost all cases.
    if (!xen_host_get_metrics(session, &metric, host->contents[0])) goto free;

    if (xen_host_metrics_get_memory_total(session, &total, metric)) ret = SYSINFO_RET_OK;

    SET_UI64_RESULT(result, total);
free:
    xen_host_metrics_free(metric);
    xen_host_set_free(host);
    xen_session_logout(session);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_network_in                                             *
 *                                                                            *
 ******************************************************************************/
static int xen_host_network_in(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_network_in";
    char                    *key;
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    key = (4 == request->nparam) ? zbx_dsprintf(NULL , "pif_%s_rx", get_rparam(request, 3)) : zbx_strdup(NULL, "pif_aggr_rx");

    ret = get_xen_host_metric(request, key, 3, result);

    zbx_free(key);

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_network_out                                             *
 *                                                                            *
 ******************************************************************************/
static int xen_host_network_out(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_network_out";
    char                    *key;
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    key = (4 == request->nparam) ? zbx_dsprintf(NULL , "pif_%s_tx", get_rparam(request, 3)) : zbx_strdup(NULL, "pif_aggr_tx");

    ret = get_xen_host_metric(request, key, 3, result);

    zbx_free(key);

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_xapi_memory_allocation                                  *
 *                                                                            *
 ******************************************************************************/
static int xen_host_xapi_memory_allocation(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_xapi_memory_allocation";
    char                    *key = "xapi_allocation_kib";
    int                     ret = SYSINFO_RET_FAIL;
    double                  memory_allocation;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    ret = get_xen_host_metric(request, key, 3, result);

    if (SYSINFO_RET_OK == ret) {
        memory_allocation = atof(result->str) * ZBX_KIBIBYTE;

        UNSET_STR_RESULT(result);
        SET_DBL_RESULT(result, memory_allocation);
    }

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_xapi_memory_free                                       *
 *                                                                            *
 ******************************************************************************/
static int xen_host_xapi_memory_free(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_xapi_memory_free";
    char                    *key = "xapi_free_memory_kib";
    int                     ret = SYSINFO_RET_FAIL;
    double                  memory_free;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    ret = get_xen_host_metric(request, key, 3, result);
    
    if (SYSINFO_RET_OK == ret) {
        memory_free = atof(result->str) * ZBX_KIBIBYTE;

        UNSET_STR_RESULT(result);
        SET_DBL_RESULT(result, memory_free);
    }

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_xapi_memory_live                                        *
 *                                                                            *
 ******************************************************************************/
static int xen_host_xapi_memory_live(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_xapi_memory_live";
    char                    *key = "xapi_live_memory_kib";
    int                     ret = SYSINFO_RET_FAIL;
    double                  memory_live;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    ret = get_xen_host_metric(request, key, 3, result);

    if (SYSINFO_RET_OK == ret) {
        UNSET_STR_RESULT(result);
        SET_DBL_RESULT(result, memory_live);
    }

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_xapi_memory_usage                                       *
 *                                                                            *
 ******************************************************************************/
static int xen_host_xapi_memory_usage(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_xapi_memory_usage";
    char                    *key = "xapi_memory_usage_kib";
    int                     ret = SYSINFO_RET_FAIL;
    double                  memory_usage;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    ret = get_xen_host_metric(request, key, 3, result);

    if (SYSINFO_RET_OK == ret) {
        UNSET_STR_RESULT(result);
        SET_DBL_RESULT(result, memory_usage);
    }

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_sr_cache_hits                                           *
 *                                                                            *
 * Comment: function not in use                                               *
 *                                                                            *
 ******************************************************************************/
static int xen_host_sr_cache_hits(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_sr_cache_hits";
    char                    *key;
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (4 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    key = zbx_dsprintf(NULL , "sr_%s_cache_hits", get_rparam(request, 3));

    ret = get_xen_host_metric(request, key, 4, result);

    zbx_free(key);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_sr_cache_misses                                         *
 *                                                                            *
 * Comment: function not in use                                               *
 *                                                                            *
 ******************************************************************************/
static int xen_host_sr_cache_misses(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_sr_cache_misses";
    char                    *key;
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (4 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    key = zbx_dsprintf(NULL , "sr_%s_cache_misses", get_rparam(request, 3));

    ret = get_xen_host_metric(request, key, 4, result);

    zbx_free(key);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_host_sr_cache_size                                           *
 *                                                                            *
 * Comment: function not in use                                               *
 *                                                                            *
 ******************************************************************************/
static int xen_host_sr_cache_size(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_host_sr_cache_size";
    char                    *key;
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (4 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    key = zbx_dsprintf(NULL , "sr_%s_cache_size", get_rparam(request, 3));

    ret = get_xen_host_metric(request, key, 4, result);

    zbx_free(key);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_sr_virtual_allocation                                        *
 *                                                                            *
 ******************************************************************************/
static int  xen_sr_virtual_allocation(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_sr_virtual_allocation";
    int                     ret = SYSINFO_RET_FAIL;
    int64_t                 value = 0;
    char                    *sr_uuid;
    xen_sr                  sr;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (4 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    url = get_rparam(request, 0);
    sr_uuid = get_rparam(request, 3);

    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;
    if (!xen_sr_get_by_uuid(session, &sr, sr_uuid)) goto free;
    if (!xen_sr_get_virtual_allocation(session, &value, sr)) goto free;

    SET_UI64_RESULT(result, value);

    ret = SYSINFO_RET_OK;
free:
    // xen_sr_free(&sr);
    xen_session_logout(session);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_sr_physical_utilisation                                      *
 *                                                                            *
 ******************************************************************************/
static int  xen_sr_physical_utilisation(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_sr_physical_utilisation";
    int                     ret = SYSINFO_RET_FAIL;
    int64_t                 value = 0;
    char                    *sr_uuid;
    xen_sr                  sr;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (4 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    url = get_rparam(request, 0);
    sr_uuid = get_rparam(request, 3);

    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;
    if (!xen_sr_get_by_uuid(session, &sr, sr_uuid)) goto free;
    if (!xen_sr_get_physical_utilisation(session, &value, sr)) goto free;

    SET_UI64_RESULT(result, value);

    ret = SYSINFO_RET_OK;
free:
    xen_session_logout(session);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_sr_physical_size                                             *
 *                                                                            *
 ******************************************************************************/
static int  xen_sr_physical_size(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_sr_physical_size";
    int                     ret = SYSINFO_RET_FAIL;
    int64_t                 value = 0;
    char                    *sr_uuid;
    xen_sr                  sr;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (4 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    url = get_rparam(request, 0);
    sr_uuid = get_rparam(request, 3);

    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;
    if (!xen_sr_get_by_uuid(session, &sr, sr_uuid)) goto free;
    if (!xen_sr_get_physical_size(session, &value, sr)) goto free;

    SET_UI64_RESULT(result, value);

    ret = SYSINFO_RET_OK;
free:
    xen_session_logout(session);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);
    return ret;
}


/******************************************************************************
 *                                                                            *
 * Function: xen_vm_cpu_discovery                                             *
 *                                                                            *
 * TODO: Use xen_vm_get_metric. Make a generic function                       *
 *                                                                            *
 ******************************************************************************/
static int xen_vm_cpu_discovery(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_vm_cpu_discovery";
    struct zbx_json         j;
    int                     i, ret = SYSINFO_RET_FAIL;
    int64_t                 numberofcpus;
    xen_vm                  vm;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (3 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    url = get_rparam(request, 0);
    char *vm_uuid = get_rparam(request, 3);

    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;
    if (!xen_vm_get_by_uuid(session, &vm, vm_uuid)) goto free;
    if (!xen_vm_get_vcpus_max(session, &numberofcpus, vm)) goto free;

    zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
    zbx_json_addarray(&j, ZBX_PROTO_TAG_DATA);

    for (i = 0; i < numberofcpus; i++)
    {
        zbx_json_addobject(&j, NULL);
        zbx_json_adduint64(&j, "{#CPUNUM}", i);
        zbx_json_close(&j);
    }

    zbx_json_close(&j);
    SET_STR_RESULT(result, zbx_strdup(NULL, j.buffer));

    ret = SYSINFO_RET_OK;
free:
    zbx_json_free(&j);
    xen_vm_free(vm);
    xen_session_logout(session);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_vm_disk_discovery                                             *
 *                                                                            *
 ******************************************************************************/
static int xen_vm_disk_discovery(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_vm_disk_discovery";
    struct zbx_json         j;
    int                     i, ret = SYSINFO_RET_FAIL;
    xen_vm                  vm;
    xen_vbd_set             *vbds;
    xen_vbd_record          *vbd;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (3 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    url = get_rparam(request, 0);
    char *vm_uuid = get_rparam(request, 3);

    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;
    if (!xen_vm_get_by_uuid(session, &vm, vm_uuid)) goto free;
    if (!xen_vm_get_vbds(session, &vbds, vm)) goto free;

    zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
    zbx_json_addarray(&j, ZBX_PROTO_TAG_DATA);

    for (i = 0; i < vbds->size; i++)
    {
        if (!xen_vbd_get_record(session, &vbd, vbds->contents[i])) goto free;
        zbx_json_addobject(&j, NULL);
        zbx_json_addstring(&j, "{#DISK.TYPE}", xen_vbd_type_to_string(vbd->type), ZBX_JSON_TYPE_STRING);
        zbx_json_addstring(&j, "{#DISK.DEVICE}", vbd->device, ZBX_JSON_TYPE_STRING);
        zbx_json_close(&j);
    }

    zbx_json_close(&j);
    SET_STR_RESULT(result, zbx_strdup(NULL, j.buffer));

    ret = SYSINFO_RET_OK;
free:
    zbx_json_free(&j);
    xen_vm_free(vm);
    xen_vbd_set_free(vbds);
    xen_vbd_record_free(vbd);
    xen_session_logout(session);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_vm_network_discovery                                         *
 *                                                                            *
 ******************************************************************************/
static int xen_vm_network_discovery(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_vm_network_discovery";
    struct zbx_json         j;
    int                     i, ret = SYSINFO_RET_FAIL;
    xen_vm                  vm;
    xen_vif_set             *vifs;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (3 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    url = get_rparam(request, 0);
    char *vm_uuid = get_rparam(request, 3);

    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;
    if (!xen_vm_get_by_uuid(session, &vm, vm_uuid)) goto free;
    if (!xen_vm_get_vifs(session, &vifs, vm)) goto free;

    zbx_json_init(&j, ZBX_JSON_STAT_BUF_LEN);
    zbx_json_addarray(&j, ZBX_PROTO_TAG_DATA);

    for (i = 0; i < vifs->size; i++)
    {
        zbx_json_addobject(&j, NULL);
        zbx_json_adduint64(&j, "{#VIF.NUMBER}", i);
        zbx_json_close(&j);
    }

    zbx_json_close(&j);
    SET_STR_RESULT(result, zbx_strdup(NULL, j.buffer));

    ret = SYSINFO_RET_OK;
free:
    xen_vm_free(vm);
    xen_vif_set_free(vifs);
    zbx_json_free(&j);
    xen_session_logout(session);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s()", __function_name);
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_vm_cpu_avg                                                   *
 *                                                                            *
 * TODO: make a function to merge get_power_state and call once               *
 *       in xen_vm_cpu_avg and xen_vm_get_metric                              *
 *                                                                            *
 ******************************************************************************/
static int xen_vm_cpu_avg(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_vm_cpu_avg";
    char                    *key = NULL, *url_api = NULL;
    int                     i, ret = SYSINFO_RET_FAIL;
    double                  avg = 0;
    int64_t                 numberofcpus;
    enum xen_vm_power_state power_state;
    xen_vm                  vm;
    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (3 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Invalid number of parameters"));
        goto end;
    }

    url = get_rparam(request, 0);
    char *vm_uuid = get_rparam(request, 3);

    if (!xen_login(get_rparam(request, 1), get_rparam(request, 2))) goto end;
    if (!xen_vm_get_by_uuid(session, &vm, vm_uuid)) goto free;
    if (!xen_vm_get_power_state(session, &power_state, vm)) goto free;
    if (power_state != XEN_VM_POWER_STATE_RUNNING)
    {
        ret = SYSINFO_RET_OK;
        SET_UI64_RESULT(result, 0);
        goto free;
    }
    if (!xen_vm_get_vcpus_max(session, &numberofcpus, vm)) goto free;

    url_api = zbx_dsprintf(NULL , "%s/vm_rrd?session_id=%s&uuid=%s", url, session->session_id, vm_uuid);

    doc = xmlReadFile(url_api, NULL, 0);

    zbx_free(url_api);

    if (doc == NULL) goto free;

    /*Get the root element node */
    root_element = xmlDocGetRootElement(doc);

    for (i = 0; i < numberofcpus; i++)
    {
        key = zbx_dsprintf(NULL , "cpu%d", i);
        //NOTE: atof convert (char *) to double
        avg += atof(search_element_value(root_element, key));
    }

    zbx_free(key);

    SET_DBL_RESULT(result, avg/i);

    ret = SYSINFO_RET_OK;
free:
    xmlFreeDoc(doc);
    xen_vm_free(vm);
    xen_session_logout(session);
end:
    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_vm_cpu_usage                                                 *
 *                                                                            *
 ******************************************************************************/
static int xen_vm_cpu_usage(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_vm_cpu_usage";
    char                    *key;
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    if (4 < request->nparam) {
        key = zbx_dsprintf(NULL , "cpu%s", get_rparam(request, 4));
        ret = get_xen_vm_metric(request, key, 4, result);
        zbx_free(key);
    }
    else {
        ret = xen_vm_cpu_avg(request, result);
    }

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_vm_disk_read                                                 *
 *                                                                            *
 ******************************************************************************/
static int xen_vm_disk_read(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_vm_disk_read";
    char                    *key;
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    key = zbx_dsprintf(NULL , "vbd_%s_read", get_rparam(request, 4));

    ret = get_xen_vm_metric(request, key, 5, result);

    zbx_free(key);

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_vm_disk_write                                                *
 *                                                                            *
 ******************************************************************************/
static int xen_vm_disk_write(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_vm_disk_write";
    char                    *key;
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    key = zbx_dsprintf(NULL , "vbd_%s_write", get_rparam(request, 4));

    ret = get_xen_vm_metric(request, key, 5, result);

    zbx_free(key);

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_vm_memory_target                                             *
 *                                                                            *
 ******************************************************************************/
static int xen_vm_memory_target(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_vm_memory_target";
    char                    *key = "memory_target";
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    ret = get_xen_vm_metric(request, key, 4, result);

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_vm_memory_total                                              *
 *                                                                            *
 ******************************************************************************/
static int xen_vm_memory_total(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_vm_memory_total";
    char                    *key = "memory";
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    ret = get_xen_vm_metric(request, key, 4, result);

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_vm_memory_free                                               *
 *                                                                            *
 ******************************************************************************/
static int xen_vm_memory_free(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_vm_memory_free";
    char                    *key = "memory_internal_free";
    int                     ret = SYSINFO_RET_FAIL;
    unsigned int            memory;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    ret = get_xen_vm_metric(request, key, 4, result);

    if (SYSINFO_RET_OK == ret) {
        memory = atoi(result->str) * ZBX_KIBIBYTE;

        UNSET_STR_RESULT(result);
        SET_UI64_RESULT(result, memory);
    }

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_vm_network_in                                                *
 *                                                                            *
 ******************************************************************************/
static int xen_vm_network_in(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_vm_network_in";
    char                    *key;
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    key = zbx_dsprintf(NULL , "vif_%s_rx", get_rparam(request, 4));

    ret = get_xen_vm_metric(request, key, 5, result);

    zbx_free(key);

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: xen_vm_network_out                                                 *
 *                                                                            *
 ******************************************************************************/
static int xen_vm_network_out(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    const char              *__function_name = "xen_vm_network_out";
    char                    *key;
    int                     ret = SYSINFO_RET_FAIL;

    zabbix_log(LOG_LEVEL_DEBUG, "In %s()", __function_name);

    key = zbx_dsprintf(NULL , "vif_%s_tx", get_rparam(request, 4));

    ret = get_xen_vm_metric(request, key, 5, result);

    zbx_free(key);

    zabbix_log(LOG_LEVEL_DEBUG, "End of %s():%s", __function_name, sysinfo_ret_string(ret));

    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: zbx_module_init                                                  *
 *                                                                            *
 * Purpose: the function is called on agent startup                           *
 *          It should be used to call any initialization routines             *
 *                                                                            *
 * Return value: ZBX_MODULE_OK - success                                      *
 *               ZBX_MODULE_FAIL - module initialization failed               *
 *                                                                            *
 * Comment: the module won't be loaded in case of ZBX_MODULE_FAIL             *
 *                                                                            *
 ******************************************************************************/
int    zbx_module_init()
{
    session = NULL;
    xmlInitParser();
    xen_init();
    curl_global_init(CURL_GLOBAL_ALL);

    return ZBX_MODULE_OK;
}

/******************************************************************************
 *                                                                            *
 * Function: zbx_module_uninit                                                *
 *                                                                            *
 * Purpose: the function is called on agent shutdown                          *
 *          It should be used to cleanup used resources if there are any      *
 *                                                                            *
 * Return value: ZBX_MODULE_OK - success                                      *
 *               ZBX_MODULE_FAIL - function failed                            *
 *                                                                            *
 ******************************************************************************/
int    zbx_module_uninit()
{
    xen_fini();
    xmlCleanupParser();
    // zbx_free(session);

    return ZBX_MODULE_OK;
}
