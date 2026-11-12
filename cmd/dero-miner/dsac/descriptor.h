/* descriptor.h -- the structure-exploiting suffix sort. See descriptor.c. */

#ifndef DSAC_DESCRIPTOR_H
#define DSAC_DESCRIPTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
/* Builds the suffix array of t[0:n] into sa[0:n].
 *
 * Returns 0 on success and a negative value otherwise, in which case sa holds
 * nothing useful and the caller must fall back to a general sorter. The result
 * is the suffix array, which is unique, so a success is bit-identical to what
 * reference SA-IS would have produced -- native\sabench.exe checks exactly that. */
int dsa_descriptor_suffix_array(const uint8_t* t, int32_t* sa, int32_t n);

#ifdef DSA_LCP
/* LCP prototype (off by default): bucket counts, see descriptor.c. */
extern unsigned long long dsa_lcp_b[4];
void dsa_lcp_reset(void);
#endif

/* derohe r30 (L-C2): 0 = the r29 two-list merge (default), 1 = the branch-free form. Bit-exact either way. */
void dsa_set_merge_variant(int v);
int dsa_get_merge_variant(void);

/* Frees this thread's scratch. Optional; mining threads live as long as the
 * process and the OS reclaims it. */
void dsa_descriptor_release(void);

#ifdef __cplusplus
}
#endif

#endif /* DSAC_DESCRIPTOR_H */
