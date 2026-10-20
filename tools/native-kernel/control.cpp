// Owned x86 fixture. Keep the explicit layout shared with the bounded experiment.
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
struct Header { int32_t* pixels; uint32_t stride; uint32_t height; };
class GridControl {
public:
    int32_t* nodes;
    uint32_t stride;
    uint32_t rows;
    Header* header;
    unsigned char reserved[0x84];
    uint32_t width;
    uint32_t height;
    __declspec(noinline) uint32_t __thiscall probe(uint32_t tag);
    __declspec(noinline) void __thiscall run();
};
static_assert(sizeof(void*)==4,"Build only for x86");
static_assert(offsetof(GridControl,width)==0x94,"Context width offset");
static_assert(offsetof(GridControl,height)==0x98,"Context height offset");
static_assert(sizeof(GridControl)==156,"Context byte count");
uint32_t __thiscall GridControl::probe(uint32_t tag) {
    nodes[0]=(int32_t)(uintptr_t)this;
    return tag ^ 0x5a17c3e9U;
}
void __thiscall GridControl::run() {
    for(uint32_t i=0;i<stride*rows;i++) nodes[i]=0;
    int32_t next=0;
    for(uint32_t x=0;;x=width) {
        for(uint32_t y=0;y<=height;y++) nodes[y*stride+x]=next++;
        if(x==width) break;
    }
    for(uint32_t y=0;;y=height) {
        for(uint32_t x=1;x<width;x++) nodes[y*stride+x]=next++;
        if(y==height) break;
    }
    for(uint32_t y=1;y<height;y++) for(uint32_t x=1;x<width;x++) {
        const uint32_t p=(y-1)*header->stride+x-1;
        const int32_t label=header->pixels[p];
        const bool differs=header->pixels[p+1]!=label || header->pixels[p+header->stride]!=label || header->pixels[p+header->stride+1]!=label;
        nodes[y*stride+x]=differs ? next++ : -1;
    }
}
extern "C" void __cdecl wirefit_control_entry() {
    for(;;) Sleep(1000);
}