/*
 *    Copyright (c) 2020 Karim <<karimdavoodi@gmail.com>>
 *
 *    Permission is hereby granted, free of charge, to any person obtaining a copy
 *    of this software and associated documentation files (the "Software"), to deal
 *    in the Software without restriction, including without limitation the rights
 *    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *    copies of the Software, and to permit persons to whom the Software is
 *    furnished to do so, subject to the following conditions:
 *
 *    The above copyright notice and this permission notice shall be included in all
 *    copies or substantial portions of the Software.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *    SOFTWARE.
 */

/**
 * SECTION:element-mpegtscrypt
 *
 * <refsect2>
 * <title>Example launch line</title>
 * |[
 * gst-launch -v -m udpsrc uri="udp://229.1.1.1" ! mpegtscrypt ! fakesink 
 * ]|
 * </refsect2>
 */

#include <gst/gst.h>
#include "gstmpegtscrypt.hpp"
#include "crypt.hpp"
    

GST_DEBUG_CATEGORY_STATIC (gst_mpegts_crypt_debug);
#define GST_CAT_DEFAULT gst_mpegts_crypt_debug

/* Filter signals and args */
enum
{
  /* FILL ME */
  LAST_SIGNAL
};


#define GST_TYPE_MPEGTSCRYPT_METHOD (gst_mpegtscrypt_method_get_type ())
static GType gst_mpegtscrypt_method_get_type (void)
{
    static GType mpegtscrypt_method_type = 0;
    if (!mpegtscrypt_method_type) {
        static GEnumValue pattern_types[] = {
            { MPEGTSCRYPT_METHOD_BISS ,       "BISS Method", "biss" },
            { MPEGTSCRYPT_METHOD_BISS_V2_1 ,  "BISS v2 Mode-1 Method", "biss_v2_mode_1" },
            // { MPEGTSCRYPT_METHOD_BISS_V2_E ,  "BISS v2 Mode-E Method", "biss_v2_mode_e" },
            // { MPEGTSCRYPT_METHOD_BISS_V2_CA , "BISS v2 Mode-CA Method", "biss_v2_mode_ca" },
            { MPEGTSCRYPT_METHOD_AES128_ECB , "AES128 ECB Method", "aes128_ecb" },
            { MPEGTSCRYPT_METHOD_AES128_CBC , "AES128 CBC Method", "aes128_cbc" },
            { MPEGTSCRYPT_METHOD_AES256_ECB , "AES256 ECB Method", "aes256_ecb" },
            { MPEGTSCRYPT_METHOD_AES256_CBC , "AES256 CBC Method", "aes256_cbc" },
            { 0, NULL, NULL },
        };
        mpegtscrypt_method_type =
            g_enum_register_static ("GstMpegTsCryptMethod",
                    pattern_types);
    }
    return mpegtscrypt_method_type;
}
#define GST_TYPE_MPEGTSCRYPT_OPERATION (gst_mpegtscrypt_operation_get_type ())
static GType gst_mpegtscrypt_operation_get_type (void)
{
    static GType mpegtscrypt_operation_type = 0;
    if (!mpegtscrypt_operation_type) {
        static GEnumValue pattern_types[] = {
            { MPEGTSCRYPT_OPERATION_DEC , "Decrypt", "dec" },
            { MPEGTSCRYPT_OPERATION_ENC , "Encrypt", "enc" },
            { 0, NULL, NULL },
        };
        mpegtscrypt_operation_type =
            g_enum_register_static ("GstMpegTsCryptOperation",
                    pattern_types);
    }
    return mpegtscrypt_operation_type;
}

static GstStaticPadTemplate sink_factory = GST_STATIC_PAD_TEMPLATE ("sink",
        GST_PAD_SINK,
        GST_PAD_ALWAYS,
        GST_STATIC_CAPS ("video/mpegts")
        );

static GstStaticPadTemplate src_factory = GST_STATIC_PAD_TEMPLATE ("src",
        GST_PAD_SRC,
        GST_PAD_ALWAYS,
        GST_STATIC_CAPS ("video/mpegts")
        );

#define gst_mpegts_crypt_parent_class parent_class
G_DEFINE_TYPE (GstMpegtsCrypt, gst_mpegts_crypt, GST_TYPE_ELEMENT);

static void gst_mpegts_crypt_set_property (GObject * object, guint prop_id,
        const GValue * value, GParamSpec * pspec);
static void gst_mpegts_crypt_get_property (GObject * object, guint prop_id,
        GValue * value, GParamSpec * pspec);

static gboolean gst_mpegts_crypt_sink_event (GstPad * pad, GstObject * parent, GstEvent * event);
static GstFlowReturn gst_mpegts_crypt_chain (GstPad * pad, GstObject * parent, GstBuffer * buf);
static GstStateChangeReturn gst_mpegts_crypt_change_state (GstElement *element, 
        GstStateChange transition)
{
    GstStateChangeReturn ret = GST_STATE_CHANGE_SUCCESS;
    GstMpegtsCrypt *filter = GST_MPEGTSCRYPT (element);
    switch (transition) {
        case GST_STATE_CHANGE_NULL_TO_READY:
            crypt_init(filter);
            break;
        default:
            break;
    }
    ret = GST_ELEMENT_CLASS (parent_class)->change_state (element, transition);
    if (ret == GST_STATE_CHANGE_FAILURE)
        return ret;
    switch (transition) {
        case GST_STATE_CHANGE_READY_TO_NULL:
            crypt_finish(filter);
            break;
        default:
            break;
    }
    return ret;
}
static void gst_mpegts_crypt_class_init (GstMpegtsCryptClass * klass)
{
    GObjectClass *gobject_class;
    GstElementClass *gstelement_class;

    gobject_class = (GObjectClass *) klass;
    gstelement_class = (GstElementClass *) klass;

    gobject_class->set_property = gst_mpegts_crypt_set_property;
    gobject_class->get_property = gst_mpegts_crypt_get_property;
    gstelement_class->change_state = gst_mpegts_crypt_change_state;

    g_object_class_install_property (gobject_class, PROP_METHOD,
            g_param_spec_enum ("method", "Method", 
                "Method of cryptography",
                GST_TYPE_MPEGTSCRYPT_METHOD,
                MPEGTSCRYPT_METHOD_BISS,
                G_PARAM_READWRITE  ));
    g_object_class_install_property (gobject_class, PROP_KEY,
            g_param_spec_string ("key", "Key", 
                "Crypto key string",
                "", G_PARAM_READWRITE ));
    g_object_class_install_property (gobject_class, PROP_OPERATION,
            g_param_spec_enum ("op", "Operartion", 
                "Cryptogrsphy operation",
                GST_TYPE_MPEGTSCRYPT_OPERATION,
                MPEGTSCRYPT_OPERATION_ENC,
                G_PARAM_READWRITE  ));

    gst_element_class_set_details_simple(gstelement_class,
            "MPEG TS Cryptogrsphy",
            "Filter",
            "Encrypt/decrypt MPEG TS by BISS or AES",
            "Karim Davoodi <<karimdavoodi@gmail.com>>");

    gst_element_class_add_pad_template (gstelement_class,
            gst_static_pad_template_get (&src_factory));
    gst_element_class_add_pad_template (gstelement_class,
            gst_static_pad_template_get (&sink_factory));
}

static void gst_mpegts_crypt_init (GstMpegtsCrypt * filter)
{
    filter->sinkpad = gst_pad_new_from_static_template (&sink_factory, "sink");
    gst_pad_set_event_function (filter->sinkpad,
            GST_DEBUG_FUNCPTR(gst_mpegts_crypt_sink_event));
    gst_pad_set_chain_function (filter->sinkpad,
            GST_DEBUG_FUNCPTR(gst_mpegts_crypt_chain));
    GST_PAD_SET_PROXY_CAPS (filter->sinkpad);
    gst_element_add_pad (GST_ELEMENT (filter), filter->sinkpad);

    filter->srcpad = gst_pad_new_from_static_template (&src_factory, "src");
    GST_PAD_SET_PROXY_CAPS (filter->srcpad);
    gst_element_add_pad (GST_ELEMENT (filter), filter->srcpad);

    filter->adapter = gst_adapter_new();
    filter->init_crypt = false;
}

    static void
gst_mpegts_crypt_set_property (GObject * object, guint prop_id,
        const GValue * value, GParamSpec * pspec)
{
    GstMpegtsCrypt *filter = GST_MPEGTSCRYPT (object);

    switch (prop_id) {
        case PROP_METHOD:
            filter->method = (GstMpegTsCryptMethod) g_value_get_enum(value);
            break;
        case PROP_OPERATION:
            filter->operation = (GstMpegTsCryptOperation) g_value_get_enum(value);
            break;
        case PROP_KEY:
            strncpy(filter->key, g_value_get_string (value), 250);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
            break;
    }
}

static void gst_mpegts_crypt_get_property (GObject * object, guint prop_id,
        GValue * value, GParamSpec * pspec)
{
    GstMpegtsCrypt *filter = GST_MPEGTSCRYPT (object);

    switch (prop_id) {
        case PROP_METHOD:
            g_value_set_enum(value, filter->method);
            break;
        case PROP_OPERATION:
            g_value_set_enum(value, filter->operation);
            break;
        case PROP_KEY:
            g_value_set_string(value, filter->key);
            break;
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
            break;
    }
}

static gboolean gst_mpegts_crypt_sink_event (GstPad * pad, GstObject * parent, 
        GstEvent * event)
{
    gboolean ret;
    GstMpegtsCrypt *filter;

    filter = GST_MPEGTSCRYPT (parent);

    switch (GST_EVENT_TYPE (event)) {
        /*
           case GST_EVENT_CAPS:
           {
           GstCaps * caps;

           gst_event_parse_caps (event, &caps);

           ret = gst_pad_event_default (pad, parent, event);
           break;
           }
           */
        default:
            ret = gst_pad_event_default (pad, parent, event);
            break;
    }
    return ret;
}

bool  check_adapter_contents_ts(GstMpegtsCrypt* filter, GstAdapter* adapter)
{
    auto data = (const unsigned char*) gst_adapter_map(adapter, TS_PACKET_SIZE);
    int k = 0;
    if(data[0] != 0x47){
        for(size_t i=0; i<TS_PACKET_SIZE; ++i){
            if(data[i] == 0x47){
                k = i;  
                break;
            }
        }
    }
    gst_adapter_unmap(adapter);
    if(k > 0){
        GST_WARNING_OBJECT(filter, "buffer not start by 0x47. ignore size %d", k);
        gst_adapter_flush(adapter, k);
        return false;
    }
    return true;
}

static GstFlowReturn gst_mpegts_crypt_chain (GstPad * pad, GstObject * parent, GstBuffer * buf)
{
    GstMpegtsCrypt *filter  = GST_MPEGTSCRYPT (parent);
    GstAdapter     *adapter = filter->adapter;
    GstFlowReturn   ret = GST_FLOW_OK;
    GstMapInfo map;

    GST_LOG_OBJECT(filter, "got buffer size:%ld", gst_buffer_get_size(buf));

    gst_adapter_push (adapter, buf);


    // while we can read out TS_PACKET_SIZE bytes, process them
    while ((gst_adapter_available (adapter) >= TS_PACKET_SIZE ) && ret == GST_FLOW_OK) {

        if(!check_adapter_contents_ts(filter, adapter)) 
            continue;

        GstBuffer* buffer = gst_adapter_take_buffer(adapter, TS_PACKET_SIZE);
        gst_buffer_map(buffer, &map, GST_MAP_READWRITE);

        switch(filter->method){
            case MPEGTSCRYPT_METHOD_BISS:
                crypt_packet_biss(filter, map.data);
                break;
            case MPEGTSCRYPT_METHOD_BISS_V2_1:
                crypt_packet_biss_v2(filter, map.data);
                break;
            // case MPEGTSCRYPT_METHOD_BISS_V2_E:
            //     crypt_packet_biss_v2(filter, map.data);
            //     break;
            // case MPEGTSCRYPT_METHOD_BISS_V2_CA:
            //     crypt_packet_biss_v2(filter, map.data);
            //     break;
            case MPEGTSCRYPT_METHOD_AES128_ECB:
            case MPEGTSCRYPT_METHOD_AES128_CBC:
            case MPEGTSCRYPT_METHOD_AES256_ECB:
            case MPEGTSCRYPT_METHOD_AES256_CBC:
                crypt_packet_aes(filter, map.data);
                break;
        }
        gst_buffer_unmap(buffer, &map);
        ret = gst_pad_push (filter->srcpad, buffer);
    }
    return ret;
}

static gboolean mpegtscrypt_init (GstPlugin * mpegtscrypt)
{
    GST_DEBUG_CATEGORY_INIT (gst_mpegts_crypt_debug, "mpegtscrypt",
            0, "Encrypt/decrypt mpegts");

    return gst_element_register (mpegtscrypt, "mpegtscrypt", GST_RANK_NONE,
            GST_TYPE_MPEGTSCRYPT);
}

#define PACKAGE "mpegtscrypt"

GST_PLUGIN_DEFINE (
        GST_VERSION_MAJOR,
        GST_VERSION_MINOR,
        mpegtscrypt,
        "Encrypt/decrypt mpegts by BISS and AES",
        mpegtscrypt_init,
        "1.0.1",
        "LGPL",
        "Gstreamer",
        "https://github.com/karimdavoodi/gst_mpegts_crypt"
        )
