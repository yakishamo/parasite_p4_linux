#include <linux/skbuff.h>
#include <linux/parasite_p4.h>

enum parasite_p4_result
parasite_p4_hook(struct sk_buff *skb, struct vport *vport) {
    return PARASITE_P4_PASS;
}
