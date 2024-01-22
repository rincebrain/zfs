
#include <libzdb.h>

const char *
zdb_ot_name(dmu_object_type_t type)
{
	if (type < DMU_OT_NUMTYPES)
		return (dmu_ot[type].ot_name);
	else if ((type & DMU_OT_NEWTYPE) &&
	    ((type & DMU_OT_BYTESWAP_MASK) < DMU_BSWAP_NUMFUNCS))
		return (dmu_ot_byteswap[type & DMU_OT_BYTESWAP_MASK].ob_name);
	else
		return ("UNKNOWN");
}

int
livelist_compare(const void *larg, const void *rarg)
{
	const blkptr_t *l = larg;
	const blkptr_t *r = rarg;

	/* Sort them according to dva[0] */
	uint64_t l_dva0_vdev, r_dva0_vdev;
	l_dva0_vdev = DVA_GET_VDEV(&l->blk_dva[0]);
	r_dva0_vdev = DVA_GET_VDEV(&r->blk_dva[0]);
	if (l_dva0_vdev < r_dva0_vdev)
		return (-1);
	else if (l_dva0_vdev > r_dva0_vdev)
		return (+1);

	/* if vdevs are equal, sort by offsets. */
	uint64_t l_dva0_offset;
	uint64_t r_dva0_offset;
	l_dva0_offset = DVA_GET_OFFSET(&l->blk_dva[0]);
	r_dva0_offset = DVA_GET_OFFSET(&r->blk_dva[0]);
	if (l_dva0_offset < r_dva0_offset) {
		return (-1);
	} else if (l_dva0_offset > r_dva0_offset) {
		return (+1);
	}

	/*
	 * Since we're storing blkptrs without cancelling FREE/ALLOC pairs,
	 * it's possible the offsets are equal. In that case, sort by txg
	 */
	if (l->blk_birth < r->blk_birth) {
		return (-1);
	} else if (l->blk_birth > r->blk_birth) {
		return (+1);
	}
	return (0);
}
