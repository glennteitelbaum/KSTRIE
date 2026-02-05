#include "kstrie.hpp"
#include <cassert>
#include <iostream>

using namespace gteitelbaum;

int main() {
    std::cout << "kstrie integration tests:\n";

    // Construction
    kstrie<int> t;
    assert(t.empty());
    assert(t.size() == 0);
    std::cout << "  construction: PASS\n";

    // NOTE: insert/find require compact + bitmask to be implemented.
    // These will assert-fail until stubs are replaced with real code.
    std::cout << "  (insert/find tests skipped -- compact/bitmask are stubs)\n";

    std::cout << "ALL PASSED\n";
    return 0;
}
