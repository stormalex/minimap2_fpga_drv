#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DP_BATCHSIZE        (127)

#define ALIGN_BYTE_N(n, v) ((v+n-1)&(~(n-1)))


typedef struct {
  int n_cigar;
  uint32_t max:31, zdropped:1;
  int max_q, max_t;      // max extension coordinate
  int mqe, mqe_t;        // max score when reaching the end of query
  int mte, mte_q;        // max score when reaching the end of target
  int score;             // max score reaching both ends; may be KSW_NEG_INF
  int reach_end;
  int m_cigar;
  int revcigar;
  int pad8B[2];
  uint32_t *cigar;
} ksw_extz_t;


typedef struct
{
  uint32_t offset;//first sw segment, from head always
  uint32_t size;//total ez size of this reg
  uint32_t midnum;//middle cnt in x86
  uint32_t regpos;
  //uint8_t  hasleft;//0 not has, non 0 has
  //uint8_t  hasright;
} sw_reghdr_t;


typedef struct
{
  uint64_t head;//node list's head
  uint32_t ctxpos;//curr read's ctx position
  uint16_t regnum;//regnum for curr read'sw
  uint16_t longsw;
  sw_reghdr_t reg;
} sw_readhdr_t;


typedef struct {
  void *   km;
  uint32_t magic;//from swring magic
  uint32_t size;
  uint16_t tid;//threadid
  uint16_t num;
  uint8_t  type;
  uint8_t  lat;
  uint16_t freecigar;
  uint8_t pad8B[8];
  sw_readhdr_t data[DP_BATCHSIZE];
} swtest_rcvhdr_t ;


static uint32_t merge_to_midnum(uint32_t midnum, int hasleft, int hasright)
{
    uint32_t ret = 0;
    if (hasleft)  ret |= midnum|0x80000000;//set bit 31 to left
    if (hasright) ret |= midnum|0x40000000;//set bit 30 to right
    return ret;
}

static int get_left(uint32_t midnum)
{
    return midnum&0x80000000;//get bit 31
}

static int get_right(uint32_t midnum)
{
    return midnum&0x40000000;//get bit 30
}

static uint32_t clear_midnum(uint32_t midnum)
{
    return midnum&0x3FFFFFFF;//clear bit 31-30
}

uint32_t *cigar_compare(ksw_extz_t *sim_ez, ksw_extz_t *fpg_ez, uint32_t *cigar_start)
{
      if (sim_ez->n_cigar != fpg_ez->n_cigar) printf("ez->ncigar err!\n");
      if (sim_ez->max != fpg_ez->max) printf("ez->max err!\n");
      //if (sim_ez-> != fpg_ez->) printf("ez->\n");
      if (sim_ez->zdropped != fpg_ez->zdropped) printf("ez->zdropped err!\n");
      if (sim_ez->max_q != fpg_ez->max_q) printf("ez->max_q err!\n");
      if (sim_ez->max_t != fpg_ez->max_t) printf("ez->max_t err!\n");
      if (sim_ez->mqe   != fpg_ez->mqe)   printf("ez->mqe   err!\n");
      if (sim_ez->mqe_t != fpg_ez->mqe_t) printf("ez->mqe_t err!\n");
      if (sim_ez->mte   != fpg_ez->mte)   printf("ez->mte   err!\n");
      if (sim_ez->mte_q != fpg_ez->mte_q) printf("ez->mte_q err!\n");
      if (sim_ez->score != fpg_ez->score) printf("ez->score err!\n");
      if (sim_ez->reach_end != fpg_ez->reach_end) printf("ez->reach_end err!\n");
      fpg_ez->cigar = cigar_start;
      if (0 != memcmp(sim_ez->cigar, fpg_ez->cigar, fpg_ez->n_cigar)) printf("cigar err!\n");
      return 0;
}
int swresult_compare(swtest_rcvhdr_t *sim, swtest_rcvhdr_t *fpg)
{
  if (sim->magic != fpg->magic) printf("magic err! 1111111111\n");
  if (sim->tid   != fpg->tid  ) printf("tid   err! 1111111111\n");
  if (sim->num   != fpg->num  ) printf("num   err! 1111111111\n");
  if (sim->type  != fpg->type ) printf("type  err! 1111111111\n");
  if (sim->lat   != fpg->lat  ) printf("last  err! 1111111111\n");
  if (sim->freecigar != 0)       printf("freecigar err!1111111111\n");

  for (int k=0; k<sim->num; k++) {
    sw_readhdr_t *sim_read = sim->data + k;
    sw_readhdr_t *fpg_read = fpg->data + k;

    sw_reghdr_t *sim_reg = &sim_read->reg;
    sw_reghdr_t *fpg_reg = &fpg_read->reg;

    if (sim_read->ctxpos != fpg_read->ctxpos) printf("read->ctxpos err!\n");
    if (sim_read->regnum != fpg_read->regnum) printf("read->regnum err!\n");
    if (sim_read->longsw != 0) printf("read->longsw err!\n");
    if (sim_reg->midnum  != fpg_reg->midnum) printf("reg->midnum err!\n");
    if (sim_reg->regpos  != fpg_reg->regpos) printf("reg->regpos err!\n");
    fpg_reg->size = (!!get_left(fpg_reg->midnum) + !!get_right(fpg_reg->midnum) + clear_midnum(fpg_reg->midnum)) * sizeof(ksw_extz_t);
    if (0 == k) fpg_reg->offset = sizeof(swtest_rcvhdr_t);
    else fpg_reg->offset = fpg->data[k-1].reg.offset + fpg->data[k-1].reg.size;

    ksw_extz_t *sim_ez = (ksw_extz_t *)((uint8_t *)sim+sim_reg->offset);
    ksw_extz_t *fpg_ez = (ksw_extz_t *)((uint8_t *)fpg+fpg_reg->offset);

    uint32_t *cigar_start = (uint32_t *)(fpg_ez + (!!get_left(fpg_reg->midnum) + !!get_right(fpg_reg->midnum) + clear_midnum(fpg_reg->midnum)));

    if (get_left(fpg_reg->midnum)) {
      cigar_compare(sim_ez, fpg_ez, cigar_start);
      cigar_start += ALIGN_BYTE_N(16, fpg_ez->n_cigar);
      fpg_ez++;
    }

    int midnums = clear_midnum(fpg_reg->midnum);
    for (int x=0; x<midnums; x++) {
      cigar_compare(sim_ez, fpg_ez, cigar_start);
      cigar_start += ALIGN_BYTE_N(16, fpg_ez->n_cigar);
      fpg_ez++;
    }

    if (get_right(fpg_reg->midnum)) {
      cigar_compare(sim_ez, fpg_ez, cigar_start);
      cigar_start += ALIGN_BYTE_N(16, fpg_ez->n_cigar);
      fpg_ez++;
    }

  }      
}
