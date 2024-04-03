# Krafton Jungle Week 11 Team 2 WIL

## Project 3 VM : Memory Management ~ Swap In/Out

---

## Supplemental Page Table

이번 프로젝트3에서 보조 페이지 테이블에 대한 설계를 진행했어야 했다.

### 보조 페이지 테이블이란?

> 이 시점에서 핀토스는 가상 및 물리 메모리 매핑을 관리하는 페이지 테이블(pml4)을 가집니다.  
> 하지만, 이것은 충분하지 않습니다. 이전 섹션에서 설명한 대로 페이지 폴트 및 자원 관리를 처리하면 각 페이지에 대한 추가 정보를 저장할 수 있는 추가 페이지 테이블도 필요합니다. 따라서 프로젝트 3의 첫 번째 작업으로 추가 페이지 테이블에 대한 몇 가지 기본 기능을 구현하는 것을 제안합니다. - GitBook

기존의 페이지 테이블은 어떠한 가상 메모리 주소에 대한 페이지와 프레임, 여러 비트들만 가지고 있었다.  
이 정보로는 가상메모리를 관리하는데 충분하지 않아 보조 페이지 테이블 필요했다.  
보조 페이지 테이블은 Page fault가 발생하면 페이지를 조회하여 그곳에 어떤 데이터가 있는지 알아내고, 프로세스가 종료될 때 보조 페이지 테이블을 참조하여 어떤 리소스를 해제할지 결정한다.

보조 페이지 테이블을 구현할 때 여러 자료 구조를 사용할 수 있는데 우리 팀은 해시 테이블을 사용했다.

## 우리 팀이 구현한 코드

```
// 보조 페이지 테이블 구조체 
struct supplemental_page_table  
{
    struct hash hash_table;
};

void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED)
{
    hash_init(&spt->hash_table, page_hash, page_less, NULL);
}
```

해시 테이블을 구현할 때는 hash.h를 참조하여 구현했다.

```
struct page *spt_find_page(struct supplemental_page_table *spt, void *va)
{
    struct page *page = NULL;
    struct hash *hash = &spt->hash_table;

    page = (struct page *)malloc(sizeof(struct page));
    page->va = pg_round_down(va);
    struct hash_elem *e = hash_find(hash, &page->h_elem);
    free(page);
    if (e == NULL)
    {
        return NULL;
    }
    page = hash_entry(e, struct page, h_elem);
    return page;
}
```

이 코드를 구현할 때 어려움이 있었다.  
hash\_find() 할 때 페이지의 &page->h\_elem을 사용하는데 저 페이지는 위에서 방금 할당한 페이지이다.  
그런데 왜 해시에서 찾아질까? 하는 의문이 있었다.  
조교님께 질문을 했고 답을 얻을 수 있었다.

[##_Image|kage@LCVWd/btsGjZ1f0lh/8WSgc5WjZKiC1ILUcCixX0/img.png|CDM|1.3|{"originWidth":657,"originHeight":429,"style":"alignCenter"}_##]

**pg\_round\_down()를 사용한 이유**  
va가 가리키는 가상 페이지의 시작을 가리켜야 코드 진행 중 다른 페이지의 영역을 침범하지 않는다.

---

```
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,struct page *page UNUSED)
{
    int succ = false;
    struct hash *hash = &spt->hash_table;

    if (hash_insert(hash, &page->h_elem) != NULL)
    {
        return succ;
    }

    succ = true;
    return succ;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page)
{
    hash_delete(&spt->hash_table, &page->h_elem);
    vm_dealloc_page(page);
    return true;
}
```

보조 페이지 테이블의 삽입과 삭제를 위한 함수

---

## 프레임

```
struct frame // 프레임 구조체 
{
    void *kva;
    struct page *page;
    struct list_elem f_elem;
};
```

프레임 테이블을 위해 list\_elem을 추가해줬다.

```
static struct frame *vm_get_frame(void)
{
    struct frame *frame = NULL; // 정적 선언
    void *kva;
    struct page *page = NULL;

    kva = palloc_get_page(PAL_USER);
    if (kva == NULL)
    {
        struct frame *victim = vm_evict_frame(); // 페이지 교체 정책
        victim->page = NULL;
        return victim;
    }

    frame = (struct frame *)malloc(sizeof(struct frame));
    frame->kva = kva;
    frame->page = page;

    lock_acquire(&vm_lock);
    list_push_back(&frame_table, &frame->f_elem);
    lock_release(&vm_lock);

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}
```

페이지에 할당해 줄 프레임을 반환해 주는 함수다.  
kva = palloc\_get\_page(PAL\_USER)은 커널 영역에 있는 유저 스택의 메모리를 가져온다.  
kva가 NULL이라면 물리 주소에 더 이상 공간이 없기 때문에 페이지 교체 정책을 실행해 준다.  
kva가 NULL이 아니라면 물리 주소와 프레임을 매핑시켜 주고 프레임 테이블에 삽입해 준다.  
이때 동시성 문제를 고려하여 lock을 사용해 주었다.

---

```
bool vm_claim_page(void *va UNUSED)
{
    struct page *page = NULL;
    struct supplemental_page_table *spt = &thread_current()->spt;

    page = spt_find_page(spt, va);
    if (page == NULL)
        return false;

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page)
{
    struct frame *frame = vm_get_frame();

    frame->page = page;
    page->frame = frame;

    struct thread *cur = thread_current();
    pml4_set_page(cur->pml4, page->va, frame->kva, page->writable);


    return swap_in(page, frame->kva);
}
```

페이지와 프레임을 매핑해 주는 함수  
보조 페이지 테이블에서 va에 해당하는 페이지를 찾아 vm\_do\_claim\_page()를 호출한다.  
vm\_do\_claim\_page()에서 vm\_get\_frame()으로 프레임을 할당받고 페이지와 프레임을 매핑시켜 준다.  
실제 페이지 테이블에도 마찬가지로 매핑시켜 준다. 이후 swap\_in()을 호출한다.

---

```
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux)
{
    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    if (spt_find_page(spt, upage) == NULL)
    {

        struct page *new_page = (struct page *)malloc(sizeof(struct page)); 

        if (VM_TYPE(type) == VM_ANON)
        {
            uninit_new(new_page, upage, init, type, aux, anon_initializer);
        }
        else if (VM_TYPE(type) == VM_FILE)
        {
            uninit_new(new_page, upage, init, type, aux, file_backed_initializer);
        }
        new_page->writable = writable;
 
        return spt_insert_page(spt, new_page);
    }
err:
    return false;
}
```

페이지 타입에 따라 새로운 페이지를 할당해주는 함수이다.

uninit 타입의 페이지를 먼저 만들어서 보조 페이지 테이블에 삽입하는 함수이다.  
페이지가 변화할 타입에 따라 다른 initializer 함수를 사용한다.

---

아래 코드를 설명하기 전 Lazy loading에 대해 알아야 한다.  
Lazy loading 이란 프로그램이 실제로 해당 데이터를 필요로 할 때까지 데이터의 로딩을 지연시키는 기법.

```
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    while (read_bytes > 0 || zero_bytes > 0)
    {
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        void *aux = NULL;

        struct necessary_info *nec = (struct necessary_info *)malloc(sizeof(struct necessary_info));
        nec->file = file;
        nec->ofs = ofs;
        nec->read_byte = page_read_bytes;
        nec->zero_byte = page_zero_bytes;
        aux = nec;

        if (!vm_alloc_page_with_initializer(VM_ANON, upage,
                                            writable, lazy_load_segment, aux))
            return false;
        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
        ofs += page_read_bytes;
    }
    return true;
}

bool lazy_load_segment(struct page *page, void *aux)
{
    struct necessary_info *nec = (struct necessary_info *)aux;

    void *kpage = page->frame->kva;

    file_seek(nec->file, nec->ofs);

    if (file_read(nec->file, kpage, nec->read_byte) != (int)nec->read_byte)
    {
        palloc_free_page(kpage);
        printf("file read fail read byte %d\n", nec->read_byte);
        return false;
    }
    memset(kpage + nec->read_byte, 0, nec->zero_byte);
    file_seek(nec->file, nec->ofs);
    return true;
}
```

load\_segment()는 lazy\_load\_segment()를 위한 전처리 작업을 해준다.  
lazy\_load\_segment()에서 필요한 정보들을 보조 구조체인 necessary\_info에 담아 aux 형태로 전달한다.

lazy\_load\_segment()는 실제로 페이지의 데이터를 복사하는 함수이다.  
demand zero memory를 위해 memset()로 0으로 세팅해 주었다.

---

```
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED, struct supplemental_page_table *src UNUSED)
{
    struct hash *src_hash = &src->hash_table;
    struct hash *dst_hash = &dst->hash_table;
    struct hash_iterator i;

    hash_first(&i, src_hash);
    while (hash_next(&i))
    {
        struct page *p = hash_entry(hash_cur(&i), struct page, h_elem);
        if (p == NULL)
            return false;
        enum vm_type type = page_get_type(p);
        struct page *child;

        if (p->operations->type == VM_UNINIT)
        {
            if (!vm_alloc_page_with_initializer(type, p->va, p->writable, p->uninit.init, p->uninit.aux))
                return false;
        }
        else
        {
            if (!vm_alloc_page(type, p->va, p->writable))
                return false;
            if (!vm_claim_page(p->va))
                return false;

            child = spt_find_page(dst, p->va);
            memcpy(child->frame->kva, p->frame->kva, PGSIZE);
        }
    }

    return true;
}

void hash_elem_destroy(struct hash_elem *e, void *aux UNUSED)
{
    struct page *p = hash_entry(e, struct page, h_elem);
    vm_dealloc_page(p);
}
/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED)
{

    struct hash *hash = &spt->hash_table;
    hash_clear(hash, hash_elem_destroy);
}
```

supplemental\_page\_table\_copy()와 supplemental\_page\_table\_kill()은 부모가 자식에게 보조 페이지 테이블 전달과 삭제를 위해 사용된다.

supplemental\_page\_table\_copy()는 자식을 위한 페이지를 할당받고 물리 메모리를 매핑한 후 부모의 물리 주소안에 있는 데이터를 자식에게 복사한다.

supplemental\_page\_table\_kill()은 보조 페이지 테이블에 있는 페이지들을 삭제하는 함수이다.  
hash\_clear()에는 보조 해시 함수가 필요한데 hash\_elem\_destroy()을 만들어주었다.

---

## Stack Growth

setup\_stack()에서 PGSIZE만큼만 할당해 주었기 때문에 그 이상을 사용하기 위해서 vm\_stack\_growth()을 사용해 주어야 한다. 메모리 효율을 위해 필요할 때마다 vm\_stack\_growth() 사용하여 스택을 늘려주어야 한다.

```
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED, bool write UNUSED, bool not_present UNUSED)
{
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    if (is_kernel_vaddr(addr))
    {
        return false;
    }
    if (addr == NULL)
    {
        return false;
    }

    if (not_present)
    {
        void *rsp;
        if (user)
            rsp = f->rsp;
        else
            rsp = thread_current()->rsp_stack;

        if (rsp - 8 <= addr && USER_STACK - 0x100000 <= rsp - 8 && addr <= USER_STACK)
        {
            vm_stack_growth(pg_round_down(addr));
        }

        page = spt_find_page(spt, addr);

        if (page == NULL)
        {
            return false;
        }
        if (write == 1 && page->writable == 0)
            return false;
        return vm_do_claim_page(page);
    }

    return false;
}
```

페이지 폴트 발생 시 exception.c에서 호출하는 핸들러다.

rsp보다 위에서 일어난 페이지 폴트만 유효한 접근이다.  
유저 스택의 크기가 1MB를 넘어선 안된다.  
이러한 조건들이 만족할 시 vm\_stack\_growth()을 호출한다.  
해당 페이지가 보조 페이지 테이블에 있을 때 물리 메모리를 할당해 준다.

```
static void vm_stack_growth(void *addr)
{
    vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), 1);
}
```

새롭게 스택에 페이지를 할당해 준다.

---

## Memory Mapped Files

```
void *mmap(void *addr, size_t length, int writable, int fd, off_t offset)
{
    // 파일의 시작점(offset)이 page-align되지 않았을 때
    if (offset % PGSIZE != 0)
    {
        return NULL;
    }
    // 가상 유저 page 시작 주소가 page-align되어있지 않을 때
    /* failure case 2: 해당 주소의 시작점이 page-align되어 있는지 & user 영역인지 & 주소값이 null인지 & length가 0이하인지*/
    if (pg_round_down(addr) != addr || is_kernel_vaddr(addr) || addr == NULL || (long long)length <= 0)
    {
        return NULL;
    }
    // 매핑하려는 페이지가 이미 존재하는 페이지와 겹칠 때(==SPT에 존재하는 페이지일 때)
    if (spt_find_page(&thread_current()->spt, addr))
    {
        return NULL;
    }

    // 콘솔 입출력과 연관된 파일 디스크립터 값(0: STDIN, 1:STDOUT)일 때
    if (fd == 0 || fd == 1)
    {
        exit(-1);
    }
    // 찾는 파일이 디스크에 없는경우
    struct file *target = find_file_descriptor(fd)->file;
    if (target == NULL)
    {
        return NULL;
    }

    return do_mmap(addr, length, writable, target, offset);
}
```

syscall.c에 있는 mmap()이다.

do\_mmap() 호출하기 위해 다양한 예외 처리를 거쳤다.

```
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset)
{
    // offset ~ length
    void *ret = addr;
    struct file *open_file = file_reopen(file);

    if (open_file == NULL)
        return NULL;

    size_t read_byte = file_length(file) < length ? file_length(file) : length;
    size_t zero_byte = PGSIZE - read_byte % PGSIZE;

    ASSERT((read_byte + zero_byte) % PGSIZE == 0);
    ASSERT(pg_ofs(addr) == 0);
    ASSERT(offset % PGSIZE == 0);

    while (read_byte > 0 || zero_byte > 0)
    {
        size_t page_read_bytes = read_byte < PGSIZE ? read_byte : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct necessary_info *nec = (struct necessary_info *)malloc(sizeof(struct necessary_info));
        nec->file = open_file;
        nec->ofs = offset;
        nec->read_byte = page_read_bytes;
        nec->zero_byte = page_zero_bytes;

        if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, nec))
            return NULL;

        read_byte -= page_read_bytes;
        zero_byte -= page_zero_bytes;
        addr += PGSIZE;
        offset += page_read_bytes;
    }

    return ret;
}
```

파일의 내용을 페이지로 매핑해주는 함수이다.  
file\_open()이 아닌 file\_reopen()을 사용한 이유는 file\_close 시에 문제가 생길 수 있기 때문에 독립적인 참조를 위해서 사용해 주었다.

파일의 내용을 페이지에 매핑해주는 함수이기 때문에 load\_segement()와 유사한 구조를 지닌다.

```
void do_munmap(void *addr)
{
    while (true)
    {
        struct thread *curr = thread_current();
        struct page *find_page = spt_find_page(&curr->spt, addr);

        if (find_page == NULL)
        {
            return NULL;
        }

        struct necessary_info *nec = (struct necessary_info *)find_page->uninit.aux;
        find_page->file.aux = nec;
        file_backed_destroy(find_page);

        addr += PGSIZE;
    }
}
```

mmap한 주소에 대해 메모리 해제를 진행한다.  
file\_backed\_destroy()을 호출해 준다.

```
static void file_backed_destroy(struct page *page)
{
    struct file_page *file_page UNUSED = &page->file;
    struct necessary_info *nec = file_page->aux;
    struct thread *curr = thread_current();

    if (pml4_is_dirty(curr->pml4, page->va))
    {
        file_write_at(nec->file, page->va, nec->read_byte, nec->ofs);
        pml4_set_dirty(curr->pml4, page->va, 0);
    }
    pml4_clear_page(curr->pml4, page->va);
}
```

파일이 변경되었다면 변경 사항을 파일에 적용시켜주고 dirty 비트를 세팅한다. 그 이후에 pml4의 페이지를 unmapping 해준다.

---

## Swap In/Out

가상 메모리의 핵심 기법이다.  
실제 물리 메모리보다 더 큰 것처럼 메모리를 사용하기 위해서 Swap In/Out을 활용한다.

```
void vm_anon_init(void)
{
    hash_init(&swap_table, anon_page_hash, anon_page_less, NULL);
    lock_init(&swap_lock);
    swap_disk = disk_get(1, 1); 

    disk_sector_t swap_size = disk_size(swap_disk) / 8;
    for (disk_sector_t i = 0; i < swap_size; i++)
    {
        struct slot *insert_disk = (struct slot *)malloc(sizeof(struct slot));
        insert_disk->used = 0;
        insert_disk->index = i;
        insert_disk->page = NULL;
        lock_acquire(&swap_lock);
        hash_insert(&swap_table, &insert_disk->swap_elem);
        lock_release(&swap_lock);
    }
}
```

anon system을 초기화해주는 함수이다.  
스왑 테이블 관리를 여러 자료 구조로 사용할 수 있지만 우리는 해시 테이블을 선택했다!

disk\_get()을 통해 스왑 디스크를 할당받았다.  
disk\_get()의 인자에 따라 디스크의 용도가 정해진다.

> Pintos uses disks this way:  
> 0:0 - boot loader, command line args, and operating system kernel  
> 0:1 - file system  
> 1:0 - scratch  
> 1:1 - swap

스왑 디스크를 사용하기 위해서 슬롯을 만드는 과정이 필요하다.  
disk\_sector\_t swap\_size = disk\_size(swap\_disk) / 8; 이 부분에서 8로 나눈 이유는  
한 슬롯이 한 페이지 담아야 하는데 한 섹터는 512바이트여서 한 섹터가 한 페이지를 담지 못한다. 이러한 이유로 8로 나눠서 8섹터가 1슬롯이 될 수 있게 스왑 사이즈를 조정했다.

```
struct slot //슬롯 구조체
{
    struct hash_elem swap_elem;
    int used; // 사용중 1, 사용가능 0
    int index;
    struct page *page;
};
```

각 슬롯은 페이지를 담을 수 있고 고유한 인덱스를 가질 수 있다.

---

```
bool anon_initializer(struct page *page, enum vm_type type, void *kva)
{
    /* Set up the handler */
    page->operations = &anon_ops;

    struct anon_page *anon_page = &page->anon;

    anon_page->slot_idx = -1;

    return true;
}
```

anon\_page->slot\_idx = -1; 슬롯에 저장되지 않은 anon\_page의 인덱스를 -1로 초기화해준다.

---

```
static bool anon_swap_out(struct page *page)
{
    if (page == NULL)
        return false;
    struct anon_page *anon_page = &page->anon;
    struct slot *slot;
    struct hash_iterator i;
    hash_first(&i, &swap_table);
    lock_acquire(&swap_lock);
    while (hash_next(&i))
    {
        slot = hash_entry(hash_cur(&i), struct slot, swap_elem);
        if (slot->used == 0)
        {
            for (int i = 0; i < 8; i++)
            {
                disk_write(swap_disk, slot->index * 8 + i, page->va + DISK_SECTOR_SIZE * i);
            }

            anon_page->slot_idx = slot->index;
            slot->page = page;
            slot->used = 1;
            page->frame->page = NULL;
            page->frame = NULL;
            pml4_clear_page(thread_current()->pml4, page->va);
            lock_release(&swap_lock);
            return true;
        }
    }
    lock_release(&swap_lock);
    PANIC("full swap disk");
}
```

스왑 디스크로 희생 페이지를 내보내는 함수이다.

반복문을 통해 해시 테이블에서 사용 가능한 슬롯을 찾는다. if (slot->used == 0)일 때 디스크에 페이지의 내용을 적어준다. used를 1로 갱신해 준다.  
나중에 swap in을 대비해서 어떤 슬롯에 내 정보가 저장되어 있는지를 확인하기 위해 아래 코드를 작성했다.

```
anon_page->slot_idx = slot->index;
```

페이지와 연결된 프레임을 해제하고 pml4에서도 unmapping 해준다.

동시성 문제를 고려하여 lock을 사용해 주었다.

---

```
static bool anon_swap_in(struct page *page, void *kva)
{
    struct anon_page *anon_page = &page->anon;
    struct slot *slot;
    disk_sector_t page_slot_index = anon_page->slot_idx;

    struct hash_iterator i;
    hash_first(&i, &swap_table);
    lock_acquire(&swap_lock);
    while (hash_next(&i))
    {
        slot = hash_entry(hash_cur(&i), struct slot, swap_elem);
        if (slot->index == page_slot_index)
        {
            for (int i = 0; i < 8; i++)
                disk_read(swap_disk, page_slot_index * 8 + i, kva + DISK_SECTOR_SIZE * i);

            slot->page = NULL;
            slot->used = 0;
            anon_page->slot_idx = -1;
            lock_release(&swap_lock);
            return true;
        }
    }
    lock_release(&swap_lock);
    return false;
}
```

디스크에서 해당 주소로 데이터를 가져오는 함수이다.  
swap out에서 정해주었던 슬롯의 인덱스와 페이지 슬롯의 인덱스가 동일하다면 disk\_read()를 진행한다.  
disk\_read() -> page\_slot\_index 8 + i을 사용한 이유는 각 슬롯이 8개의 섹터를 가지고 있기 때문이다. disk\_read() -> kva + DISK\_SECTOR\_SIZE i는 각 섹터의 크기만큼 오프셋을 이동하기 위해 사용했다.

페이지를 swap in했으므로 해당 페이지의 슬롯 인덱스를 -1로 갱신했다.

---

```
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva)
{
    /* Set up the handler */
    page->operations = &file_ops;

    struct file_page *file_page = &page->file;

    file_page->aux = page->uninit.aux;

    return true;
}
```

swap in을 위해서 page->uninit.aux를 file\_page->aux에 받아왔다.

```
static bool file_backed_swap_out(struct page *page)
{
    struct file_page *file_page UNUSED = &page->file;
    if(page==NULL){
		return false;
	}
    struct necessary_info *nec = file_page->aux;
    struct file* file = nec->file;
    lock_acquire(&file_lock);
    if(pml4_is_dirty(thread_current()->pml4,page->va)){
		file_write_at(file,page->va, nec->read_byte, nec->ofs);
		pml4_set_dirty(thread_current()->pml4, page->va, 0);
	}
	pml4_clear_page(thread_current()->pml4, page->va);
    lock_release(&file_lock);
	return true;
}
```

file-backed는 anon과 달리 스왑 디스크가 아니라 파일에 스왑한다.  
페이지의 내용이 변경된 적이 있다면 변경된 내용을 파일 갱신하고 dirty 비트를 0으로 변경한다.  
이후 pml4\_clear\_page() 사용했다.

```
static bool file_backed_swap_in(struct page *page, void *kva)
{
    struct file_page *file_page UNUSED = &page->file;
    struct necessary_info *nec = (struct necessary_info *)file_page->aux;

    file_seek(nec->file, nec->ofs);
    lock_acquire(&file_lock);
    file_read(file_page->file, kva, nec->read_byte);
    lock_release(&file_lock);

    memset(kva + nec->read_byte, 0, nec->zero_byte);

    return true;
}
```

file\_seek()를 통해 파일의 오프셋을 변경해 주고 파일에서 물리 메모리로 데이터를 가져온다.  
이후 memset()을 통해 제로 바이트 영역을 0으로 세팅해 주었다.

---

## 페이지 교체 정책 - Clock

```
static struct frame *vm_get_victim(void)
{
    struct frame *victim = NULL;
    /* Clock Algorithm */
    struct list_elem *e;
    lock_acquire(&vm_lock);
    for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
    {
        victim = list_entry(e, struct frame, f_elem);
        if (victim->page == NULL)
        {
            lock_release(&vm_lock);
            return victim;
        }
        if (pml4_is_accessed(thread_current()->pml4, victim->page->va))
            pml4_set_accessed(thread_current()->pml4, victim->page->va, 0);

        else
        {
            lock_release(&vm_lock);
            return victim;
        }
    }
    lock_release(&vm_lock);
    return victim;
}
```

Clock 페이지 교체 정책이다.

프레임 테이블을 돌며 희생 페이지가 NULL이면 그 페이지를 바로 반환하고 NULL이 아니면 accessed 비트를 확인한다. accessed 비트가 1이면 0으로 바꿔주고 0이면 그 페이지를 반환한다.

---

# 프로젝트 3 - 트러블 슈팅

### vm\_get\_frame()

vm\_get\_frame()에서 프레임을 반환하는 과정에서 프레임에 메모리 할당을 하지 않았던 문제가 있었다.  
malloc()을 통해 프레임을 동적 할당해 주었다.

### free() vs palloc\_free\_page()

palloc\_get\_page()로 할당한 메모리를 free()를 통해 해제하려 했기 때문에 문제가 발생했다.

malloc()을 해주면 free()를 해주어야 하고 palloc\_get\_page()를 하면 palloc\_free\_page()를 해주어야 한다. 내부 함수 구조가 다르기 때문에 맞춰주지 않으면 에러가 난다.

### hash function

```
unsigned anon_page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
    const struct slot *p = hash_entry(p_, struct slot, swap_elem);
    return hash_bytes(&p->index, sizeof p->index);
}

bool anon_page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
    const struct slot *a = hash_entry(a_, struct slot, swap_elem);
    const struct slot *b = hash_entry(b_, struct slot, swap_elem);

    return a->index < b->index;
}
```

스왑 테이블에서 사용하는 해시 함수들이다.  
기존 해시 함수는 page->va를 이용해 해시를 저장한다. 그러나 스왑 테이블에서는 slot->page == NULL 일 수 있기 때문에 함수가 제대로 작동하지 않았다. 그래서 각 슬롯의 고유 인덱스를 통해 해시를 저장할 수 있게 했다.

### syscall read

```
int read(int fd, void *buffer, unsigned size)
{
    if (buffer == NULL || fd < 0 || !is_user_vaddr(buffer))
        exit(-1);
    struct page *p = spt_find_page(&thread_current()->spt, buffer);

    off_t buff_size;
    if (fd == 0)
    {
        return input_getc();
    }
    else if (fd == NULL || fd == 1)
    {
        return -1;
    }
    else
    {
        struct file_descriptor *read_fd = find_file_descriptor(fd);
        if (read_fd == NULL)
            return -1;
        if (p && !p->writable)
            exit(-1);

        lock_acquire(&filesys_lock);
        buff_size = file_read(read_fd->file, buffer, size);
        lock_release(&filesys_lock);
    }
    return buff_size;
}
```

```
    if (p && !p->writable)
        exit(-1);
```

위 조건이 필요한 이유는 버퍼에 파일을 읽어온 내용을 저장해야 하기 때문에 p->writable이 0이면 파일 쓰기 권한이 없기 때문에 버퍼에 작성이 불가능하여 오류가 발생했다. 따라서 위 조건을 추가해 주어 문제를 해결했다.

### syscall write

```
int write(int fd, const void *buffer, unsigned size)
{
    if (buffer == NULL || !is_user_vaddr(buffer) || fd < 0)
        exit(-1);
    struct page *p = spt_find_page(&thread_current()->spt, buffer);
    if (p == NULL)
        exit(-1);
    if (fd == 1)
    {
        putbuf(buffer, size);
        return size;
    }
    else if (fd < 0 || fd == NULL)
    {
        exit(-1);
    }
    struct file_descriptor *write_fd = find_file_descriptor(fd);
    if (write_fd == NULL)
        return -1;
    // if (p && !p->writable) // 해당 조건 삭제 
    //     exit(-1);
    lock_acquire(&filesys_lock);
    off_t write_size = file_write(write_fd->file, buffer, size); 
    lock_release(&filesys_lock);
    return write_size;
}
```

write의 경우 위의 read와 다르게 버퍼에 쓰는 것이 아니라 파일에 쓰는 것이 때문에 파일에 대한 쓰기 권한을 확인해 주어야 한다. 이에 맞게 아래 코드로 수정해 주었다.

```
if (write_fd->file && write_fd->file->deny_write)
	exit(-1);
```

### vm\_do\_claim\_page()

-   변경 전 코드

```
static bool vm_do_claim_page(struct page *page)
{
    struct frame *frame = vm_get_frame();

    frame->page = page;
    page->frame = frame;

    struct thread *cur = thread_current();
    pml4_set_page(cur->pml4, page->va, frame->kva, page->writable);
     if (pml4_get_page(cur->pml4, pg_round_down(page->va)) || !pml4_set_page(cur->pml4, pg_round_down(page->va), pg_round_down(frame->kva), page->writable))
     {
         return false;
     }

    return swap_in(page, frame->kva);
}
```

-   변경 후 코드

```
static bool vm_do_claim_page(struct page *page)
{
    struct frame *frame = vm_get_frame();

    frame->page = page;
    page->frame = frame;

    struct thread *cur = thread_current();
    pml4_set_page(cur->pml4, page->va, frame->kva, page->writable);


    return swap_in(page, frame->kva);
}
```

lazy loading 때문에 물리 페이지에 할당이 안 되어 있는 상태였다. 그래서 pml4\_get\_page()을 사용하면 오류가 발생했다. 아래 조건 코드를 빼주었다.

```
pml4_get_page(thread_current()->pml4, buffer) == NULL
```

### FIFO

```
static struct frame *
vm_get_victim(void)
{
    struct frame *victim = NULL;
    /* FIFO */
    lock_acquire(&vm_lock);
    struct list_elem *e = list_pop_front(&frame_table);
    lock_release(&vm_lock);
    victim = list_entry(e, struct frame, f_elem);

    lock_release(&vm_lock);
    return victim;
}

static struct frame *
vm_evict_frame(void)
{
    struct frame *victim UNUSED = vm_get_victim();
    if (swap_out(victim->page))
    {
        list_push_back(&frame_table, &victim->f_elem); // FIFO
        return victim;
    }

    return NULL;
}
```

원래 구현한 FIFO에서는 프레임 리스트에서 프레임을 삭제했다. 그 결과 프레임 리스트가 빈 상태여서 더 이상 희생 프레임을 가져오지 못하는 오류가 발생했다.  
해결책으로 swap\_out() 이후 아래 코드를 추가해 주었다.

```
list_push_back(&frame_table, &victim->f_elem); // FIFO
```

### memset()

```
static bool file_backed_swap_in(struct page *page, void *kva)
{
    struct file_page *file_page UNUSED = &page->file;
    struct necessary_info *nec = (struct necessary_info *)file_page->aux;

    file_seek(nec->file, nec->ofs);
    lock_acquire(&file_lock);
    file_read(file_page->file, kva, nec->read_byte);
    lock_release(&file_lock);

    memset(kva + nec->read_byte, 0, nec->zero_byte);

    return true;
}
```
