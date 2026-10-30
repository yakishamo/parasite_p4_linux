#include <linux/skbuff.h>
#include <linux/parasite_p4.h>

parasite_p4_callback_t parasite_p4_callback = NULL;
EXPORT_SYMBOL_GPL(parasite_p4_callback);

enum parasite_p4_result
parasite_p4_hook(struct sk_buff *skb, struct vport *vport) {
    if(!parasite_p4_callback) {
        return PARASITE_P4_NOCALLBACK;
    } 
    return parasite_p4_callback(skb, vport);
}
