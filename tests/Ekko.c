#include <Flower.h>

_Noreturn
FUNC VOID Start() {
    while ( TRUE ) {
        Flower( 10000, FLOWER_EKKO_OBF | FLOWER_STACKSPOOF | FLOWER_GADGET_RBX );
    }
}
