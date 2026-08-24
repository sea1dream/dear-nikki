#include <bits/stdc++.h>

#include <ext/pb_ds/assoc_container.hpp>
#include <ext/pb_ds/tree_policy.hpp>
using namespace std;

// 使用 GCC 扩展（bits、PBDS、__int128 和 __builtin_*），请选 GNU++17 或更高。
#if __cplusplus < 201703L
#error "This template requires GNU C++17 or later."
#endif

// #include <boost/multiprecision/cpp_int.hpp>
// using Big = boost::multiprecision::uint256_t;
using i64 = long long;
using i128 = __int128_t;
using u64 = unsigned long long;
using u128 = __uint128_t;
using ll = long long;
using ull = unsigned long long;
using f32 = float;
using f64 = double;
using f80 = long double;

using pii = pair<int, int>;
using pll = pair<i64, i64>;

using vi = vector<int>;
using vvi = vector<vi>;
using vll = vector<i64>;
using vvll = vector<vll>;

// C++ 没有 min=/max= 运算符；返回 true 表示 value 确实被更新。
// 两个参数故意要求同类型，避免隐式窄化以及有符号/无符号混合比较。
template <typename T>
constexpr bool chmin(T& value, const T& candidate) {
    if (candidate < value) {
        value = candidate;
        return true;
    }
    return false;
}

template <typename T>
constexpr bool chmax(T& value, const T& candidate) {
    if (value < candidate) {
        value = candidate;
        return true;
    }
    return false;
}

// unordered_* 的随机盐哈希：缓解针对固定桶分布构造碰撞的数据。
// 操作仍然只是期望/均摊 O(1)，最坏 O(n)；单次插入还可能因 rehash 为 O(n)。
// reserve_hash 可减少扩容和碰撞，但不会改变上述最坏复杂度。
// 这里按容器元素个数计复杂度；字符串哈希另需 O(|key|)，比较代价另计。
struct custom_hash {
   private:
    static constexpr u64 splitmix64(u64 x) noexcept {
        x += 0x9e3779b97f4a7c15ULL;
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
        return x ^ (x >> 31);
    }

    static u64 seed() noexcept {
        static const u64 value = []() noexcept {
            const u64 now = static_cast<u64>(
                std::chrono::steady_clock::now().time_since_epoch().count());
            const u64 address = static_cast<u64>(
                reinterpret_cast<std::uintptr_t>(&now));
            return splitmix64(now ^ address);
        }();
        return value;
    }

    static u64 mix(u64 value) noexcept {
        return splitmix64(value + seed());
    }

    static constexpr u64 combine(u64 first, u64 second) noexcept {
        return splitmix64(first ^
                          (second + 0x9e3779b97f4a7c15ULL + (first << 6) +
                           (first >> 2)));
    }

   public:
    template <typename T,
              std::enable_if_t<(std::is_integral_v<T> || std::is_enum_v<T>) &&
                                   sizeof(T) <= sizeof(u64),
                               int> = 0>
    std::size_t operator()(T value) const noexcept {
        return static_cast<std::size_t>(mix(static_cast<u64>(value)));
    }

    // 128 位整数需要同时混合高、低 64 位，不能直接截断。
    std::size_t operator()(u128 value) const noexcept {
        const u64 low = static_cast<u64>(value);
        const u64 high = static_cast<u64>(value >> 64);
        return static_cast<std::size_t>(combine(mix(low), mix(high)));
    }

    std::size_t operator()(i128 value) const noexcept {
        return (*this)(static_cast<u128>(value));
    }

    // 不在 std::hash<string> 的结果外再套一层，而是带盐混合每个字节，
    // 避免保留 std::hash<string> 本身的碰撞。
    std::size_t operator()(std::string_view value) const noexcept {
        u64 result = splitmix64(
            seed() ^ (static_cast<u64>(value.size()) +
                      0x9e3779b97f4a7c15ULL));
        for (unsigned char byte : value) {
            result = splitmix64(
                result ^ (static_cast<u64>(byte) + 0x9e3779b97f4a7c15ULL));
        }
        return static_cast<std::size_t>(result);
    }

    std::size_t operator()(const std::string& value) const noexcept {
        return (*this)(std::string_view(value.data(), value.size()));
    }

    template <typename First, typename Second>
    std::size_t operator()(
        const std::pair<First, Second>& value) const noexcept {
        const u64 first = static_cast<u64>((*this)(value.first));
        const u64 second = static_cast<u64>((*this)(value.second));
        return static_cast<std::size_t>(combine(first, second));
    }
};

template <typename Key>
using safe_unordered_set = std::unordered_set<Key, custom_hash>;

template <typename Key, typename Value>
using safe_unordered_map = std::unordered_map<Key, Value, custom_hash>;

template <typename HashTable>
void reserve_hash(HashTable& table, std::size_t expected_size) {
    table.max_load_factor(0.7f);  // 必须先设置负载因子，再 reserve。
    table.reserve(expected_size);
}

// PBDS 顺序统计树（GCC 扩展，洛谷选择 GNU++17/20 时可用）
template <typename Key, typename Compare = std::less<Key>>
using ordered_set =
    __gnu_pbds::tree<Key, __gnu_pbds::null_type, Compare,
                     __gnu_pbds::rb_tree_tag,
                     __gnu_pbds::tree_order_statistics_node_update>;

// 支持重复值的顺序统计树。不要用 less_equal 伪造 multiset：
// less_equal 不是严格弱序，会破坏 PBDS 的查找、排名和删除。
template <typename T>
class ordered_multiset {
    using key_type = std::pair<T, u64>;
    using tree_type = ordered_set<key_type>;

   public:
    using size_type = typename tree_type::size_type;

    bool empty() const { return tree_.empty(); }
    size_type size() const { return tree_.size(); }

    void clear() {
        tree_.clear();
        next_id_ = 0;
    }

    void insert(const T& value) {
        assert(next_id_ != std::numeric_limits<u64>::max());
        tree_.insert({value, next_id_++});
    }

    // 删除任意一个等于 value 的元素；成功时返回 true。
    bool erase_one(const T& value) {
        auto it = tree_.lower_bound({value, 0});
        if (it == tree_.end() || it->first != value) return false;
        tree_.erase(it);
        return true;
    }

    size_type count_less(const T& value) const {
        return tree_.order_of_key({value, 0});
    }

    size_type count_less_equal(const T& value) const {
        return tree_.order_of_key({value, std::numeric_limits<u64>::max()});
    }

    size_type count(const T& value) const {
        return count_less_equal(value) - count_less(value);
    }

    // 返回第 k 小的值（k 从 0 开始）；越界时返回 nullopt。
    std::optional<T> kth(size_type k) const {
        auto it = tree_.find_by_order(k);
        if (it == tree_.end()) return std::nullopt;
        return it->first;
    }

   private:
    tree_type tree_;
    u64 next_id_ = 0;
};

// 参数必须是生命周期稳定、无副作用的容器左值
#define all(x) std::begin(x), std::end(x)

// 要求 x >= 0；lowbit(0) == 0；返回对应的无符号类型
template <typename T>
constexpr auto lowbit(T x) noexcept {
    static_assert(std::is_integral_v<T> && !std::is_same_v<T, bool>);

    if constexpr (std::is_signed_v<T>) {
        assert(x >= 0);
    }

    using U = std::make_unsigned_t<T>;
    const U u = static_cast<U>(x);
    return u & (U{0} - u);
}

// GCC 位运算内置函数的安全封装（支持不超过 64 位的整数）
namespace bitop {

template <typename T>
constexpr auto to_unsigned(T x) noexcept {
    using V = std::remove_cv_t<T>;
    static_assert(std::is_integral_v<V> && !std::is_same_v<V, bool>);

    using U = std::make_unsigned_t<V>;
    static_assert(std::numeric_limits<U>::digits <=
                  std::numeric_limits<unsigned long long>::digits);
    return static_cast<U>(x);
}

// 二进制中 1 的个数：__builtin_popcountll
template <typename T>
constexpr int popcount(T x) noexcept {
    const auto u = to_unsigned(x);
    return __builtin_popcountll(static_cast<unsigned long long>(u));
}

// 前导零个数：与 __builtin_clz/clzll 不同，x == 0 时返回类型位数
template <typename T>
constexpr int countl_zero(T x) noexcept {
    const auto u = to_unsigned(x);
    using U = decltype(u);
    constexpr int width = std::numeric_limits<U>::digits;
    constexpr int ull_width = std::numeric_limits<unsigned long long>::digits;

    if (u == 0) return width;
    return __builtin_clzll(static_cast<unsigned long long>(u)) -
           (ull_width - width);
}

// 后缀零个数：与 __builtin_ctz/ctzll 不同，x == 0 时返回类型位数
template <typename T>
constexpr int countr_zero(T x) noexcept {
    const auto u = to_unsigned(x);
    using U = decltype(u);
    constexpr int width = std::numeric_limits<U>::digits;

    if (u == 0) return width;
    return __builtin_ctzll(static_cast<unsigned long long>(u));
}

// 最低位 1 的位置（从 1 开始）；x == 0 时返回 0，等价于 __builtin_ffsll
template <typename T>
constexpr int first_one(T x) noexcept {
    const auto u = to_unsigned(x);
    return u == 0 ? 0 : countr_zero(u) + 1;
}

template <typename T>
constexpr int bit_width(T x) noexcept {
    const auto u = to_unsigned(x);
    using U = decltype(u);
    return std::numeric_limits<U>::digits - countl_zero(u);
}

// 最高/最低位 1 的下标（从 0 开始）；x == 0 时返回 -1
template <typename T>
constexpr int msb_index(T x) noexcept {
    return bit_width(x) - 1;
}

template <typename T>
constexpr int lsb_index(T x) noexcept {
    const auto u = to_unsigned(x);
    return u == 0 ? -1 : countr_zero(u);
}

template <typename T>
constexpr bool has_single_bit(T x) noexcept {
    return popcount(x) == 1;
}

template <typename T>
constexpr int parity(T x) noexcept {
    const auto u = to_unsigned(x);
    return __builtin_parityll(static_cast<unsigned long long>(u));
}

constexpr uint16_t bswap16(uint16_t x) noexcept { return __builtin_bswap16(x); }

constexpr uint32_t bswap32(uint32_t x) noexcept { return __builtin_bswap32(x); }

constexpr uint64_t bswap64(uint64_t x) noexcept { return __builtin_bswap64(x); }

}  // namespace bitop

// 返回 true 表示发生溢出；result 会被写入转换后的运算结果
namespace checked {

template <typename A, typename B, typename R>
constexpr bool add(A a, B b, R& result) noexcept {
    static_assert(std::is_integral_v<A> && std::is_integral_v<B> &&
                  std::is_integral_v<R> && !std::is_same_v<R, bool>);
    return __builtin_add_overflow(a, b, &result);
}

template <typename A, typename B, typename R>
constexpr bool sub(A a, B b, R& result) noexcept {
    static_assert(std::is_integral_v<A> && std::is_integral_v<B> &&
                  std::is_integral_v<R> && !std::is_same_v<R, bool>);
    return __builtin_sub_overflow(a, b, &result);
}

template <typename A, typename B, typename R>
constexpr bool mul(A a, B b, R& result) noexcept {
    static_assert(std::is_integral_v<A> && std::is_integral_v<B> &&
                  std::is_integral_v<R> && !std::is_same_v<R, bool>);
    return __builtin_mul_overflow(a, b, &result);
}

}  // namespace checked

// 位运算使用示例（可复制到 solve 中运行）：
// 位运算函数建议传入无符号整数；负数会被当作同宽度的无符号值处理。
//
// {
//     u64 x = 40;  // 二进制为 101000，第 5 位和第 3 位是 1
//
//     // 1. 统计二进制中 1 的数量
//     int ones = bitop::popcount(x);  // 2
//
//     // 2. 统计前导零和后缀零
//     // u64 通常为 64 位，所以 40 前面有 64 - 6 = 58 个零。
//     int leading_zeros = bitop::countl_zero(x);   // 58
//     int trailing_zeros = bitop::countr_zero(x); // 3
//     // 与原始 __builtin_clzll/__builtin_ctzll 不同，封装允许传 0：
//     int zero_leading = bitop::countl_zero(0ULL);   // 64
//     int zero_trailing = bitop::countr_zero(0ULL); // 64
//
//     // 3. 寻找最低位和最高位的 1
//     int first = bitop::first_one(x); // 4，从 1 开始，等价于 ffs 语义
//     int high = bitop::msb_index(x);  // 5，从 0 开始
//     int low = bitop::lsb_index(x);   // 3，从 0 开始
//     // 对于 x == 0，msb_index 和 lsb_index 都返回 -1。
//
//     // 4. 计算表示 x 所需的二进制位数
//     int len = bitop::bit_width(x); // 6，因为 40 的二进制是 101000
//     // x > 0 时：msb_index(x) == floor(log2(x))。
//     // bit_width(x) == floor(log2(x)) + 1，且不会有浮点精度问题。
//
//     // 5. 判断是否为 2 的幂，以及 1 的数量的奇偶性
//     bool power2 = bitop::has_single_bit(x); // false，40 有两个 1
//     int odd_ones = bitop::parity(x);        // 0，两个 1 是偶数个
//     bool eight_is_power2 =
//         bitop::has_single_bit(8ULL);         // true，8 == 2^3
//
//     // 6. lowbit 返回最低位 1 所代表的数值
//     u64 lowest_value = lowbit(x); // 8，因为最低位 1 在第 3 位
//     // 三个相关结果的区别：
//     // lowbit(40) == 8，lsb_index(40) == 3，first_one(40) == 4。
//
//     // 7. 不使用浮点数求不超过 x 的最大 2 的幂（要求 x > 0）
//     u64 highest_power = 1ULL << bitop::msb_index(x); // 32
//
//     // 8. 遍历 mask 中所有为 1 的位
//     u64 mask = x;
//     while (mask != 0) {
//         int bit = bitop::lsb_index(mask);
//         // 此处处理第 bit 个元素；x == 40 时依次得到 3、5。
//         mask &= mask - 1; // 删除当前最低位的 1
//     }
//
//     // 9. 反转字节顺序，注意这不是反转每一个二进制位
//     uint32_t swapped = bitop::bswap32(0x12345678U);
//     // swapped == 0x78563412U
// }
//
// 整数溢出检测示例：
//
// {
//     // 返回 true 表示发生溢出；没有溢出时才能使用 result。
//     // 是否溢出由结果变量的类型决定。
//     int result32 = 0;
//     bool overflow32 =
//         checked::add(INT_MAX, 1, result32); // true，超出 int 范围
//
//     i64 result64 = 0;
//     bool overflow64 =
//         checked::add(INT_MAX, 1, result64); // false
//     // result64 == 2147483648LL
//
//     i64 product = 0;
//     bool mul_overflow = checked::mul(
//         4'000'000'000LL, 4'000'000'000LL, product); // true
//
//     i64 difference = 0;
//     bool sub_overflow = checked::sub(
//         numeric_limits<i64>::min(), 1LL, difference); // true
//
//     if (!mul_overflow) {
//         // 只有没有溢出时，product 才是可用的精确结果。
//         cout << product << '\n';
//     }
// }

// 本地调试输出
///----------

#ifdef LOCAL

namespace dbg_detail {

template <typename T, typename = void>
struct is_streamable : std::false_type {};

template <typename T>
struct is_streamable<T, std::void_t<decltype(std::declval<std::ostream&>()
                                             << std::declval<const T&>())>>
    : std::true_type {};

template <typename T, typename = void>
struct is_range : std::false_type {};

template <typename T>
struct is_range<T, std::void_t<decltype(std::begin(std::declval<const T&>())),
                               decltype(std::end(std::declval<const T&>()))>>
    : std::true_type {};

template <typename T>
struct is_pair : std::false_type {};

template <typename A, typename B>
struct is_pair<std::pair<A, B>> : std::true_type {};

template <typename T>
void print_one(std::ostream& os, const T& value) {
    using Raw = std::remove_reference_t<T>;
    using U = std::decay_t<T>;

    constexpr bool non_char_array =
        std::is_array_v<Raw> &&
        !std::is_same_v<std::remove_cv_t<std::remove_extent_t<Raw>>, char>;

    if constexpr (is_pair<U>::value) {
        os << '(';
        print_one(os, value.first);
        os << ", ";
        print_one(os, value.second);
        os << ')';
    } else if constexpr (non_char_array ||
                         (is_range<Raw>::value && !is_streamable<U>::value)) {
        os << '[';
        bool first = true;

        for (const auto& item : value) {
            if (!first) os << ", ";
            first = false;
            print_one(os, item);
        }

        os << ']';
    } else if constexpr (is_streamable<U>::value) {
        os << value;
    } else {
        os << "<unprintable>";
    }
}

inline void print_many() { std::cerr << '\n'; }

template <typename First, typename... Rest>
void print_many(const First& first, const Rest&... rest) {
    print_one(std::cerr, first);
    ((std::cerr << ", ", print_one(std::cerr, rest)), ...);
    std::cerr << '\n';
}

}  // namespace dbg_detail

#define dbg(...)                                    \
    do {                                            \
        std::cerr << "[" << #__VA_ARGS__ << "] = "; \
        ::dbg_detail::print_many(__VA_ARGS__);      \
    } while (false)

#else

#define dbg(...) ((void)0)

#endif

///----------

template <typename T>
vector<T> make_v(size_t n, T value) {
    return vector<T>(n, value);
}

template <typename... Args>
auto make_v(size_t n, Args... args) {
    auto inner = make_v(args...);
    return vector<decltype(inner)>(n, inner);
}

// dbg 使用示例（仅在定义 LOCAL 时向 cerr 输出，提交时不定义 LOCAL）：
// int x = 7;
// vi a{1, 2, 3};
// pii p{4, 5};
// int raw[]{6, 7, 8};
// dbg(x);          // [x] = 7
// dbg(a, p);       // [a, p] = [1, 2, 3], (4, 5)
// dbg(raw);        // [raw] = [6, 7, 8]

// make_v 使用示例（最后一个参数决定最内层元素的类型和初值）：
// auto a1 = make_v(n, -1);                 // vector<int>(n, -1)
// auto dp = make_v(n + 1, m + 1, 0LL);     // 二维 vector<i64>，初值为 0
// auto dis = make_v(n, m, INF64);           // 二维 vector<i64>，初值为 INF64
// auto vis = make_v(n, m, false);           // 二维 vector<bool>，初值为 false
// auto memo = make_v(n, m, k, -1LL);        // 三维 vector<i64>，初值为 -1

// chmin/chmax 使用示例：
// i64 best = INF64;
// bool changed = chmin(best, 100LL);  // best = 100，changed = true
// chmin(best, 120LL);                 // best 不变；可以忽略返回值
// chmax(best, 200LL);                 // best = 200
// 注意参数类型必须一致，例如 i64 变量搭配 3LL 或 i64{3}。

// 随机盐哈希使用示例（C++17 查询用 find，不用 C++20 的 contains）：
// safe_unordered_set<i64> seen;
// reserve_hash(seen, n);  // 已知最多插入 n 个元素时，先预留容量。
// seen.insert(x);
// bool exists = seen.find(x) != seen.end();
// seen.erase(x);
//
// safe_unordered_set<pii> edges;            // pair 可直接作为键
// safe_unordered_set<string> names;         // string 会逐字节带盐哈希
// safe_unordered_map<pii, i64> edge_weight; // map 同理
// unordered_set<i64, custom_hash> raw;      // 也可给标准容器显式传哈希
//
// 若整数键严格位于 [0, U)，直接寻址才有最坏情况严格 O(1)：
// vector<unsigned char> present(U);  // 构造和内存为 O(U)
// present[x] = 1;                    // 插入
// bool has_x = present[x] != 0;      // 查询
// present[x] = 0;                    // 删除

// PBDS 使用示例：
// ordered_set<int> os;
// os.insert(10);
// os.insert(20);
// os.insert(30);
// auto less_than_20 = os.order_of_key(20);  // 1：严格小于 20 的数量
// auto it = os.find_by_order(1);            // 下标从 0 开始，指向第 2 小
// if (it != os.end()) cout << *it << '\n';  // 20；越界时 it == end()
// os.erase(20);
//
// ordered_multiset<int> ms;
// ms.insert(5);
// ms.insert(5);
// ms.insert(8);
// ms.count_less(5);        // 0
// ms.count_less_equal(5);  // 2
// ms.count(5);             // 2
// ms.kth(1);               // optional<int>{5}，第 2 小
// ms.erase_one(5);         // 删除一个 5，返回 true
// // x 的 1-based 排名：ms.count_less(x) + 1
// // 前驱的 0-based 位置：ms.count_less(x) - 1
// // 后继的 0-based 位置：ms.count_less_equal(x)

// 64 位安全模乘；要求 mod != 0。
constexpr u64 mul_mod(u64 a, u64 b, u64 mod) noexcept {
    assert(mod != 0);
    return static_cast<u64>(static_cast<u128>(a) * b % mod);
}

// 快速幂计算 (a^b) % mod；要求 mod != 0。
// 参数使用 u64，乘法使用 u128 中间值，支持完整 u64 范围。
constexpr u64 quick_power(u64 a, u64 b, u64 mod) noexcept {
    assert(mod != 0);
    u64 res = 1 % mod;
    a %= mod;
    while (b > 0) {
        if (b & 1) res = mul_mod(res, a, mod);
        a = mul_mod(a, a, mod);
        b >>= 1;
    }
    return res;
}

// 确定性 Miller-Rabin 素性测试，适用于完整 u64 范围。
// 复杂度 O(7 log n)，基底集合不能随意删减。
bool miller_rabin(u64 n) noexcept {
    if (n < 2) return false;
    static constexpr u64 small_primes[] = {2,  3,  5,  7,  11, 13,
                                           17, 19, 23, 29, 31, 37};
    for (u64 p : small_primes) {
        if (n % p == 0) return n == p;
    }

    u64 d = n - 1;
    int s = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        ++s;
    }

    static constexpr u64 bases[] = {2,       325,       9'375,        28'178,
                                    450'775, 9'780'504, 1'795'265'022};
    for (u64 a : bases) {
        if (a % n == 0) continue;
        u64 x = quick_power(a, d, n);
        if (x == 1 || x == n - 1) continue;

        bool reached_minus_one = false;
        for (int r = 1; r < s; r++) {
            x = mul_mod(x, x, n);
            if (x == n - 1) {
                reached_minus_one = true;
                break;
            }
        }
        if (!reached_minus_one) return false;
    }
    return true;
}

// 质数模数下的阶乘、逆阶乘、排列数和组合数。
// ensure(n) 按需扩容到 n；扩容总复杂度 O(新增长度)，已预处理查询 O(1)。
// P/C 的阶乘表公式要求 0 <= n < modulus；n >= modulus 时应按题使用
// Lucas 定理或其他算法，不能继续套用阶乘与逆阶乘公式。
// 构造时会验证模数；不满足条件会抛出 invalid_argument/out_of_range。
// 两张 u64 表约占用 16 * (prepared() + 1) 字节。
class PrimeComb {
   public:
    explicit PrimeComb(u64 modulus, u64 initial_n = 0)
        : modulus_(modulus), factorial_{1}, inverse_factorial_{1} {
        if (!miller_rabin(modulus_)) {
            throw std::invalid_argument("PrimeComb: modulus must be prime");
        }
        ensure(initial_n);
    }

    u64 modulus() const noexcept { return modulus_; }

    u64 prepared() const noexcept {
        return static_cast<u64>(factorial_.size() - 1);
    }

    void ensure(u64 n) {
        require_table_index(n);
        const size_t target = checked_index(n);
        if (target < factorial_.size()) return;

        if (target >= factorial_.max_size() ||
            target >= inverse_factorial_.max_size()) {
            throw std::length_error("PrimeComb: table is too large");
        }

        const size_t old_size = factorial_.size();
        factorial_.resize(target + 1);
        inverse_factorial_.resize(target + 1);

        for (size_t i = old_size; i <= target; ++i) {
            const u64 x = static_cast<u64>(i);
            u64 inverse_x = 1;

            if (x > 1) {
                // modulus = q*x + r，可推出 inv(x) = -q*inv(r)。
                const u64 remainder = modulus_ % x;
                assert(remainder != 0);

                // inv(r) = (r-1)! / r!
                const size_t r = static_cast<size_t>(remainder);
                const u64 inverse_r =
                    mul_mod(factorial_[r - 1], inverse_factorial_[r], modulus_);
                const u64 term = mul_mod(modulus_ / x, inverse_r, modulus_);
                assert(term != 0);
                inverse_x = modulus_ - term;
            }

            factorial_[i] = mul_mod(factorial_[i - 1], x, modulus_);
            inverse_factorial_[i] =
                mul_mod(inverse_factorial_[i - 1], inverse_x, modulus_);
        }
    }

    // 返回 n! mod modulus。n >= modulus 时结果必为 0。
    u64 factorial(u64 n) {
        if (n >= modulus_) return 0;
        ensure(n);
        return factorial_[static_cast<size_t>(n)];
    }

    // 返回 (n!)^(-1) mod modulus；仅在 n < modulus 时存在。
    u64 inverse_factorial(u64 n) {
        ensure(n);
        return inverse_factorial_[static_cast<size_t>(n)];
    }

    // P(n, k) = n! / (n-k)!
    u64 P(u64 n, u64 k) {
        if (k > n) return 0;
        ensure(n);

        const size_t nn = static_cast<size_t>(n);
        const size_t nk = static_cast<size_t>(n - k);
        return mul_mod(factorial_[nn], inverse_factorial_[nk], modulus_);
    }

    // C(n, k) = n! / (k!(n-k)!)
    u64 C(u64 n, u64 k) {
        if (k > n) return 0;
        ensure(n);

        const size_t nn = static_cast<size_t>(n);
        const size_t kk = static_cast<size_t>(k);
        const size_t nk = static_cast<size_t>(n - k);
        const u64 denominator =
            mul_mod(inverse_factorial_[kk], inverse_factorial_[nk], modulus_);
        return mul_mod(factorial_[nn], denominator, modulus_);
    }

   private:
    void require_table_index(u64 n) const {
        if (n >= modulus_) {
            throw std::out_of_range(
                "PrimeComb: P/C tables require n < modulus; consider "
                "Lucas theorem");
        }
    }

    static size_t checked_index(u64 n) {
        if (static_cast<u128>(n) + 1 >
            static_cast<u128>(std::numeric_limits<size_t>::max())) {
            throw std::length_error("PrimeComb: table is too large");
        }
        return static_cast<size_t>(n);
    }

    u64 modulus_;
    vector<u64> factorial_;
    vector<u64> inverse_factorial_;
};

// PrimeComb 使用示例（结果均对 modulus 取模）：
// PrimeComb comb(1'000'000'007ULL, 100'000); // 可在构造时预处理
// comb.factorial(10);         // 3628800，即 10!
// comb.inverse_factorial(10); // 10! 的乘法逆元
// comb.P(10, 3);              // 720，即 10*9*8
// comb.C(10, 3);              // 120
// comb.C(10, 11);             // 0，k > n
// comb.ensure(200'000);       // 之后可线性增量扩容，不会缩小已有表

// 扩展欧几里得、模逆、线性同余、广义 CRT，以及数论中的 Möbius 反演。
namespace nt {

struct ExgcdResult {
    u64 gcd;
    i128 x;
    i128 y;
};

namespace detail {

// 不能直接对 LLONG_MIN 调用 abs；先提升到 i128 再取绝对值。
constexpr u64 magnitude(i64 value) noexcept {
    const i128 wide = static_cast<i128>(value);
    return static_cast<u64>(wide < 0 ? -wide : wide);
}

constexpr u64 normalize_mod(i128 value, u64 modulus) noexcept {
    assert(modulus != 0);
    const i128 wide_modulus = static_cast<i128>(modulus);
    value %= wide_modulus;
    if (value < 0) value += wide_modulus;
    return static_cast<u64>(value);
}

}  // namespace detail

// 返回 gcd >= 0 且 a*x + b*y = gcd。
// gcd 用 u64，因 gcd(LLONG_MIN, 0) = 2^63；(0, 0) 返回 {0, 0, 0}。
constexpr ExgcdResult exgcd(i64 a, i64 b) noexcept {
    i128 r0 = static_cast<i128>(a);
    i128 r1 = static_cast<i128>(b);
    const bool negative_a = r0 < 0;
    const bool negative_b = r1 < 0;
    if (negative_a) r0 = -r0;
    if (negative_b) r1 = -r1;

    if (r0 == 0 && r1 == 0) return {0, 0, 0};

    i128 x0 = 1;
    i128 x1 = 0;
    i128 y0 = 0;
    i128 y1 = 1;
    while (r1 != 0) {
        const i128 quotient = r0 / r1;
        const i128 next_r = r0 - quotient * r1;
        const i128 next_x = x0 - quotient * x1;
        const i128 next_y = y0 - quotient * y1;
        r0 = r1;
        r1 = next_r;
        x0 = x1;
        x1 = next_x;
        y0 = y1;
        y1 = next_y;
    }

    if (negative_a) x0 = -x0;
    if (negative_b) y0 = -y0;
    return {static_cast<u64>(r0), x0, y0};
}

// modulus 可为负并按其绝对值处理；modulus == 0 非法。
// 无逆元返回 nullopt；模数为 +/-1 时唯一的规范剩余是 0。
inline optional<u64> inverse_mod(i64 value, i64 modulus) {
    if (modulus == 0) {
        throw std::invalid_argument("inverse_mod: modulus must be non-zero");
    }
    const ExgcdResult result = exgcd(value, modulus);
    if (result.gcd != 1) return nullopt;
    return detail::normalize_mod(result.x, detail::magnitude(modulus));
}

struct LinearCongruence {
    u64 residue;
    u64 modulus;
};

// 求 a*x == b (mod modulus)。有解时全部解为
// x == residue (mod 返回的 modulus)，且 residue 是规范剩余。
inline optional<LinearCongruence> solve_linear_congruence(i64 a, i64 b,
                                                          i64 modulus) {
    if (modulus == 0) {
        throw std::invalid_argument(
            "solve_linear_congruence: modulus must be non-zero");
    }

    const ExgcdResult result = exgcd(a, modulus);
    const i128 gcd = static_cast<i128>(result.gcd);
    if (static_cast<i128>(b) % gcd != 0) return nullopt;

    const u64 period = detail::magnitude(modulus) / result.gcd;
    const i128 solution = result.x * (static_cast<i128>(b) / gcd);
    return LinearCongruence{detail::normalize_mod(solution, period), period};
}

struct CRTResult {
    i128 residue;
    i128 modulus;
};

// 两式广义 CRT：模数无需互质，负模数按绝对值处理。
// 返回 x == residue (mod modulus)；不相容返回 nullopt，零模数抛异常。
// 两个 i64 模数的最小公倍数可能接近 2^126，故结果使用 i128。
inline optional<CRTResult> crt_pair(i64 residue1, i64 modulus1, i64 residue2,
                                    i64 modulus2) {
    if (modulus1 == 0 || modulus2 == 0) {
        throw std::invalid_argument("crt_pair: moduli must be non-zero");
    }

    const u64 positive_modulus1 = detail::magnitude(modulus1);
    const u64 positive_modulus2 = detail::magnitude(modulus2);
    const u64 normalized1 =
        detail::normalize_mod(static_cast<i128>(residue1), positive_modulus1);
    const u64 normalized2 =
        detail::normalize_mod(static_cast<i128>(residue2), positive_modulus2);

    const ExgcdResult result = exgcd(modulus1, modulus2);
    const i128 difference =
        static_cast<i128>(normalized2) - static_cast<i128>(normalized1);
    const i128 gcd = static_cast<i128>(result.gcd);
    if (difference % gcd != 0) return nullopt;

    // result.x 对应带符号的 modulus1，先转成正模数的 Bézout 系数。
    const i128 inverse = modulus1 < 0 ? -result.x : result.x;
    const u64 step_modulus = positive_modulus2 / result.gcd;
    const u64 step =
        detail::normalize_mod((difference / gcd) * inverse, step_modulus);
    const i128 lcm = static_cast<i128>(positive_modulus1 / result.gcd) *
                     static_cast<i128>(positive_modulus2);
    i128 answer = static_cast<i128>(normalized1) +
                  static_cast<i128>(positive_modulus1) * step;
    answer %= lcm;
    if (answer < 0) answer += lcm;
    return CRTResult{answer, lcm};
}

// 线性筛同时求 mu[1..limit] 和 Mertens 前缀和。
// mu[0] = 0，mu[1] = 1，mertens[x] = sum_{i=1}^x mu[i]。
// 字段公开便于直接查询；四种变换要求此表由下方线性筛生成且未被修改。
struct MobiusTable {
    int limit = 0;
    vector<int> primes;
    vector<int> mu{0};
    vector<i64> mertens{0};
};

// 时间、空间均为 O(limit)。
inline MobiusTable linear_mobius_sieve(int limit) {
    if (limit < 0) {
        throw std::invalid_argument(
            "linear_mobius_sieve: limit must be non-negative");
    }

    MobiusTable result;
    result.limit = limit;
    const size_t size = static_cast<size_t>(limit) + 1;
    result.mu.assign(size, 0);
    result.mertens.assign(size, 0);
    vector<unsigned char> composite(size);
    if (limit >= 1) result.mu[1] = 1;

    for (size_t i = 2; i < size; ++i) {
        if (!composite[i]) {
            result.primes.push_back(static_cast<int>(i));
            result.mu[i] = -1;
        }
        for (int prime : result.primes) {
            const size_t p = static_cast<size_t>(prime);
            if (p > static_cast<size_t>(limit) / i) break;
            const size_t value = i * p;
            composite[value] = 1;
            if (i % p == 0) {
                result.mu[value] = 0;
                break;
            }
            result.mu[value] = -result.mu[i];
        }
    }

    for (size_t i = 1; i < size; ++i) {
        result.mertens[i] = result.mertens[i - 1] + result.mu[i];
    }
    return result;
}

namespace detail {

inline i64 normalize_i64_mod(i64 value, i64 modulus) noexcept {
    value %= modulus;
    if (value < 0) value += modulus;
    return value;
}

inline i64 add_mod(i64 a, i64 b, i64 modulus) noexcept {
    assert(0 <= a && a < modulus && 0 <= b && b < modulus);
    return a >= modulus - b ? a - (modulus - b) : a + b;
}

inline i64 sub_mod(i64 a, i64 b, i64 modulus) noexcept {
    assert(0 <= a && a < modulus && 0 <= b && b < modulus);
    return a >= b ? a - b : modulus - (b - a);
}

inline int checked_divisibility_transform(const vector<i64>& values,
                                          const MobiusTable& table,
                                          i64 modulus) {
    if (modulus <= 0) {
        throw std::invalid_argument(
            "divisibility transform: modulus must be positive");
    }
    if (values.empty()) {
        throw std::invalid_argument(
            "divisibility transform: index 0 placeholder is required");
    }

    const size_t n = values.size() - 1;
    if (n > static_cast<size_t>(std::numeric_limits<int>::max())) {
        throw std::length_error("divisibility transform: range is too large");
    }
    if (table.limit < static_cast<int>(n) || table.mu.size() <= n ||
        table.mertens.size() <= n) {
        throw std::out_of_range(
            "divisibility transform: Mobius table is too small");
    }
    return static_cast<int>(n);
}

inline void normalize_from_one(vector<i64>& values, i64 modulus) noexcept {
    for (size_t i = 1; i < values.size(); ++i) {
        values[i] = normalize_i64_mod(values[i], modulus);
    }
}

}  // namespace detail

// 下列四种变换只处理下标 1..n，values[0] 是占位符且保持不变。
// 任意正 i64 模数均可（包括 1、偶数和合数）；单次复杂度
// sum_{p<=n} floor(n/p) = O(n log log n)，额外空间 O(1)。

// F[x] = sum_{d|x} f[d]。
inline void divisor_zeta_transform(vector<i64>& values,
                                   const MobiusTable& table, i64 modulus) {
    const int n =
        detail::checked_divisibility_transform(values, table, modulus);
    detail::normalize_from_one(values, modulus);
    for (int prime : table.primes) {
        if (prime > n) break;
        for (int i = 1, end = n / prime; i <= end; ++i) {
            values[i * prime] =
                detail::add_mod(values[i * prime], values[i], modulus);
        }
    }
}

// f[x] = sum_{d|x} mu[d] * F[x/d]，是 divisor_zeta_transform 的逆。
inline void divisor_mobius_transform(vector<i64>& values,
                                     const MobiusTable& table, i64 modulus) {
    const int n =
        detail::checked_divisibility_transform(values, table, modulus);
    detail::normalize_from_one(values, modulus);
    for (int prime : table.primes) {
        if (prime > n) break;
        for (int i = n / prime; i >= 1; --i) {
            values[i * prime] =
                detail::sub_mod(values[i * prime], values[i], modulus);
        }
    }
}

// F[x] = sum_{x|multiple, multiple<=n} f[multiple]。
inline void multiple_zeta_transform(vector<i64>& values,
                                    const MobiusTable& table, i64 modulus) {
    const int n =
        detail::checked_divisibility_transform(values, table, modulus);
    detail::normalize_from_one(values, modulus);
    for (int prime : table.primes) {
        if (prime > n) break;
        for (int i = n / prime; i >= 1; --i) {
            values[i] = detail::add_mod(values[i], values[i * prime], modulus);
        }
    }
}

// f[x] = sum_{k<=n/x} mu[k] * F[x*k]，是 multiple_zeta_transform 的逆。
inline void multiple_mobius_transform(vector<i64>& values,
                                      const MobiusTable& table, i64 modulus) {
    const int n =
        detail::checked_divisibility_transform(values, table, modulus);
    detail::normalize_from_one(values, modulus);
    for (int prime : table.primes) {
        if (prime > n) break;
        for (int i = 1, end = n / prime; i <= end; ++i) {
            values[i] = detail::sub_mod(values[i], values[i * prime], modulus);
        }
    }
}

}  // namespace nt

// exGCD / Möbius 使用示例：
// auto eg = nt::exgcd(-30, 18);  // gcd=6，且 -30*eg.x+18*eg.y=6
// auto inv = nt::inverse_mod(3, 11);  // 4
// auto equation = nt::solve_linear_congruence(6, 8, 14); // x=6 (mod 7)
// auto crt = nt::crt_pair(2, 6, 5, 9);                  // x=14 (mod 18)
// auto mobius = nt::linear_mobius_sieve(1'000'000);
// vector<i64> arithmetic_values(n + 1);  // 下标 0 仅占位
// nt::divisor_zeta_transform(arithmetic_values, mobius, 1'000'000'007);
// nt::divisor_mobius_transform(arithmetic_values, mobius, 1'000'000'007);

// 第一类（无符号/有符号）与第二类斯特林数。
// c(n,k)=c(n-1,k-1)+(n-1)c(n-1,k)，有符号 s 将加号改为减号；
// S(n,k)=S(n-1,k-1)+k*S(n-1,k)。
// make_row 只保留第 n 行，O(n^2) 时间、O(n) 空间；make_table 保存 0..n 行，
// O(n^2) 时间和空间。结果统一对任意正 i64 modulus 取模。
namespace stirling {

enum class Kind { FirstUnsigned, FirstSigned, Second };

using Row = vector<u64>;
using Table = vector<Row>;

namespace detail {

inline u64 checked_modulus(i64 modulus) {
    if (modulus <= 0) {
        throw std::invalid_argument("Stirling modulus must be positive");
    }
    return static_cast<u64>(modulus);
}

inline void require_kind(Kind kind) {
    if (kind != Kind::FirstUnsigned && kind != Kind::FirstSigned &&
        kind != Kind::Second) {
        throw std::invalid_argument("unknown Stirling number kind");
    }
}

inline void require_order(size_t order) {
    if (order == std::numeric_limits<size_t>::max()) {
        throw std::length_error("Stirling order is too large");
    }
}

constexpr u64 add_mod(u64 a, u64 b, u64 modulus) noexcept {
    assert(a < modulus && b < modulus);
    return a >= modulus - b ? a - (modulus - b) : a + b;
}

constexpr u64 sub_mod(u64 a, u64 b, u64 modulus) noexcept {
    assert(a < modulus && b < modulus);
    return a >= b ? a - b : modulus - (b - a);
}

inline u64 transition(u64 lower, u64 same, size_t n, size_t k, Kind kind,
                      u64 modulus) noexcept {
    const size_t raw_factor = kind == Kind::Second ? k : n - 1;
    const u64 factor = static_cast<u64>(static_cast<u128>(raw_factor) %
                                        static_cast<u128>(modulus));
    const u64 product = ::mul_mod(same, factor, modulus);
    return kind == Kind::FirstSigned ? sub_mod(lower, product, modulus)
                                     : add_mod(lower, product, modulus);
}

}  // namespace detail

// 返回 [T(n,0), T(n,1), ..., T(n,n)]。
inline Row make_row(size_t n, Kind kind, i64 modulus) {
    detail::require_order(n);
    detail::require_kind(kind);
    const u64 mod = detail::checked_modulus(modulus);

    Row row(n + 1);
    row[0] = 1 % mod;
    for (size_t current = 1; current <= n; ++current) {
        for (size_t k = current; k >= 1; --k) {
            row[k] =
                detail::transition(row[k - 1], row[k], current, k, kind, mod);
        }
        row[0] = 0;
    }
    return row;
}

// 返回三角表 table[n][k]；k > n 时请用 get(table,n,k) 安全查询。
inline Table make_table(size_t max_n, Kind kind, i64 modulus) {
    detail::require_order(max_n);
    detail::require_kind(kind);
    const u64 mod = detail::checked_modulus(modulus);

    Table table;
    if (max_n >= table.max_size()) {
        throw std::length_error("Stirling table is too large");
    }
    table.reserve(max_n + 1);
    table.push_back(Row{1 % mod});
    for (size_t n = 1; n <= max_n; ++n) {
        const Row& previous = table.back();
        Row current(n + 1);
        for (size_t k = 1; k <= n; ++k) {
            const u64 same = k < previous.size() ? previous[k] : 0;
            current[k] =
                detail::transition(previous[k - 1], same, n, k, kind, mod);
        }
        table.push_back(std::move(current));
    }
    return table;
}

inline u64 get(const Row& row, size_t k) noexcept {
    return k < row.size() ? row[k] : 0;
}

inline u64 get(const Table& table, size_t n, size_t k) {
    if (n >= table.size()) {
        throw std::out_of_range("Stirling row was not prepared");
    }
    return k < table[n].size() ? table[n][k] : 0;
}

inline Row first_unsigned_row(size_t n, i64 modulus) {
    return make_row(n, Kind::FirstUnsigned, modulus);
}

inline Row first_signed_row(size_t n, i64 modulus) {
    return make_row(n, Kind::FirstSigned, modulus);
}

inline Row second_row(size_t n, i64 modulus) {
    return make_row(n, Kind::Second, modulus);
}

inline Table first_unsigned_table(size_t n, i64 modulus) {
    return make_table(n, Kind::FirstUnsigned, modulus);
}

inline Table first_signed_table(size_t n, i64 modulus) {
    return make_table(n, Kind::FirstSigned, modulus);
}

inline Table second_table(size_t n, i64 modulus) {
    return make_table(n, Kind::Second, modulus);
}

}  // namespace stirling

// Stirling 使用示例（signed_first 的负数以模意义表示）：
// auto first = stirling::first_unsigned_row(4, 1'000'000'007);
// // first = {0, 6, 11, 6, 1}
// auto signed_first = stirling::first_signed_row(4, 1'000'000'007);
// auto second = stirling::second_row(5, 1'000'000'007);
// // second = {0, 1, 15, 25, 10, 1}
// auto all_second = stirling::second_table(1000, 1'000'000'007);
// stirling::get(all_second, 1000, 20);  // S(1000,20)

// 多项式卷积：浮点 FFT、998244353 NTT、任意正 int 模 MTT、拆系数 FFT。
// 四种 convolution_* 都允许负输入，空数组返回空数组，结果长度为 n+m-1。
namespace poly {

using FFTReal = long double;
using FFTComplex = std::complex<FFTReal>;
static_assert(std::numeric_limits<FFTReal>::digits >= 64,
              "FFT templates require an extended-precision long double");

namespace detail {

template <typename T>
constexpr bool is_coefficient_v =
    std::is_integral_v<T> && !std::is_same_v<T, bool> &&
    sizeof(T) <= sizeof(u64);

constexpr std::size_t FFT_SAFE_MAX_LENGTH = std::size_t{1} << 20;
constexpr u128 FFT_SAFE_INTEGER_BOUND =
    static_cast<u128>(1'000'000'000'000'000ULL);

template <typename T>
u64 magnitude(T value) {
    static_assert(is_coefficient_v<T>);
    if constexpr (std::is_signed_v<T>) {
        const i128 wide = static_cast<i128>(value);
        return static_cast<u64>(wide < 0 ? -wide : wide);
    } else {
        return static_cast<u64>(value);
    }
}

inline bool exceeds_fft_bound(std::size_t terms, u64 max_a, u64 max_b) {
    if (max_a == 0 || max_b == 0) return false;
    const u128 product = static_cast<u128>(max_a) * max_b;
    return product > FFT_SAFE_INTEGER_BOUND ||
           static_cast<u128>(terms) > FFT_SAFE_INTEGER_BOUND / product;
}

inline std::size_t convolution_size(std::size_t a_size, std::size_t b_size) {
    if (a_size == 0 || b_size == 0) return 0;
    if (a_size > std::numeric_limits<std::size_t>::max() - b_size + 1) {
        throw std::length_error("convolution length overflow");
    }
    return a_size + b_size - 1;
}

inline std::size_t transform_size(std::size_t result_size) {
    if (result_size == 0) return 0;
    std::size_t size = 1;
    while (size < result_size) {
        if (size > std::numeric_limits<std::size_t>::max() / 2) {
            throw std::length_error("transform length overflow");
        }
        size <<= 1;
    }
    return size;
}

template <typename T>
u64 normalize_mod(T value, u64 modulus) {
    static_assert(is_coefficient_v<T>,
                  "polynomial coefficients must be <= 64-bit integers");
    assert(modulus != 0);
    if constexpr (std::is_signed_v<T>) {
        i128 result = static_cast<i128>(value) % static_cast<i128>(modulus);
        if (result < 0) result += static_cast<i128>(modulus);
        return static_cast<u64>(result);
    } else {
        return static_cast<u64>(value) % modulus;
    }
}

inline i64 round_to_i64(FFTReal value) {
    const FFTReal rounded = std::round(value);
    const FFTReal lower = static_cast<FFTReal>(std::numeric_limits<i64>::min());
    const FFTReal upper_exclusive = -lower;
    if (!std::isfinite(rounded) || rounded < lower ||
        rounded >= upper_exclusive) {
        throw std::overflow_error("FFT convolution result does not fit i64");
    }
    return static_cast<i64>(rounded);
}

inline u64 ceil_sqrt(u64 value) {
    u64 result = static_cast<u64>(std::sqrt(static_cast<FFTReal>(value)));
    while (static_cast<u128>(result) * result < value) ++result;
    while (result > 0 &&
           static_cast<u128>(result - 1) * (result - 1) >= value) {
        --result;
    }
    return result;
}

}  // namespace detail

// 原地 FFT；inverse=false 为正变换，inverse=true 为逆变换。
// 空数组是 no-op；非空数组长度必须是 2 的幂。
// 单位根按层缓存来减少累计漂移，适合竞赛中的单线程调用。
inline void fft(std::vector<FFTComplex>& values, bool inverse) {
    const std::size_t size = values.size();
    if (size == 0) return;
    if ((size & (size - 1)) != 0) {
        throw std::invalid_argument("FFT length must be a power of two");
    }

    if (inverse) {
        for (FFTComplex& value : values) value = std::conj(value);
    }

    for (std::size_t i = 1, j = 0; i < size; ++i) {
        std::size_t bit = size >> 1;
        while (j & bit) {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if (i < j) std::swap(values[i], values[j]);
    }

    static std::vector<FFTComplex> roots{FFTComplex(0, 0), FFTComplex(1, 0)};
    static const FFTReal pi = std::acos(-1.0L);
    while (roots.size() < size) {
        const std::size_t half = roots.size();
        roots.resize(half << 1);
        const FFTReal angle = pi / static_cast<FFTReal>(half);
        const FFTComplex step(std::cos(angle), std::sin(angle));
        for (std::size_t i = half >> 1; i < half; ++i) {
            roots[i << 1] = roots[i];
            roots[(i << 1) | 1] = roots[i] * step;
        }
    }

    for (std::size_t half = 1; half < size; half <<= 1) {
        for (std::size_t left = 0; left < size; left += half << 1) {
            for (std::size_t i = 0; i < half; ++i) {
                const FFTComplex even = values[left + i];
                const FFTComplex odd =
                    values[left + i + half] * roots[half + i];
                values[left + i] = even + odd;
                values[left + i + half] = even - odd;
            }
        }
    }

    if (inverse) {
        const FFTReal inverse_size = 1 / static_cast<FFTReal>(size);
        for (FFTComplex& value : values) {
            value = std::conj(value) * inverse_size;
        }
    }
}

// 普通整数 FFT 卷积。精确结果必须能装入 i64；浮点 FFT 没有绝对精度保证。
// 为避免极限数据静默舍入错误，要求变换长度 <= 2^20，且
// min(n,m)*max(abs(a))*max(abs(b)) <= 1e15；否则抛异常。
template <typename A, typename B>
std::vector<i64> convolution_fft(const std::vector<A>& a,
                                 const std::vector<B>& b) {
    static_assert(detail::is_coefficient_v<A> && detail::is_coefficient_v<B>,
                  "polynomial coefficients must be <= 64-bit integers");
    const std::size_t result_size =
        detail::convolution_size(a.size(), b.size());
    if (result_size == 0) return {};
    const std::size_t size = detail::transform_size(result_size);
    if (size > detail::FFT_SAFE_MAX_LENGTH) {
        throw std::length_error("FFT length exceeds safe limit");
    }

    u64 max_a = 0, max_b = 0;
    for (const A& value : a) {
        max_a = std::max(max_a, detail::magnitude(value));
    }
    for (const B& value : b) {
        max_b = std::max(max_b, detail::magnitude(value));
    }
    if (detail::exceeds_fft_bound(std::min(a.size(), b.size()), max_a, max_b)) {
        throw std::overflow_error("FFT precision bound exceeded; use NTT/MTT");
    }

    std::vector<FFTComplex> fa(size), fb(size);
    for (std::size_t i = 0; i < a.size(); ++i) {
        fa[i] = static_cast<FFTReal>(a[i]);
    }
    for (std::size_t i = 0; i < b.size(); ++i) {
        fb[i] = static_cast<FFTReal>(b[i]);
    }

    fft(fa, false);
    fft(fb, false);
    for (std::size_t i = 0; i < size; ++i) fa[i] *= fb[i];
    fft(fa, true);

    std::vector<i64> result(result_size);
    for (std::size_t i = 0; i < result_size; ++i) {
        result[i] = detail::round_to_i64(fa[i].real());
    }
    return result;
}

// 泛型 NTT 核。Mod 必须是质数，PrimitiveRoot 必须是其原根，且
// 2^MaxPower | (Mod-1)。transform 会自动把输入归一化到 [0, Mod)。
template <std::uint32_t Mod, std::uint32_t PrimitiveRoot, int MaxPower>
class NTT {
    static_assert(Mod > 2 && Mod < (std::uint32_t{1} << 31));
    static_assert(MaxPower > 0 &&
                  MaxPower < std::numeric_limits<std::size_t>::digits);

   public:
    static constexpr std::uint32_t modulus = Mod;
    static constexpr std::size_t max_length = std::size_t{1} << MaxPower;
    static_assert((static_cast<u64>(Mod) - 1) % max_length == 0);

    static void transform(std::vector<std::uint32_t>& values, bool inverse) {
        const std::size_t size = values.size();
        if (size == 0) return;
        if ((size & (size - 1)) != 0) {
            throw std::invalid_argument("NTT length must be a power of two");
        }
        if (size > max_length) {
            throw std::length_error("NTT length exceeds modulus capacity");
        }

        for (std::uint32_t& value : values) {
            if (value >= Mod) value %= Mod;
        }
        for (std::size_t i = 1, j = 0; i < size; ++i) {
            std::size_t bit = size >> 1;
            while (j & bit) {
                j ^= bit;
                bit >>= 1;
            }
            j ^= bit;
            if (i < j) std::swap(values[i], values[j]);
        }

        for (std::size_t length = 2; length <= size; length <<= 1) {
            u64 root = quick_power(
                PrimitiveRoot,
                (static_cast<u64>(Mod) - 1) / static_cast<u64>(length), Mod);
            if (inverse) root = quick_power(root, Mod - 2, Mod);
            const std::size_t half = length >> 1;
            for (std::size_t left = 0; left < size; left += length) {
                u64 power = 1;
                for (std::size_t i = 0; i < half; ++i) {
                    const std::uint32_t even = values[left + i];
                    const std::uint32_t odd = static_cast<std::uint32_t>(
                        static_cast<u64>(values[left + i + half]) * power %
                        Mod);
                    std::uint32_t sum = even + odd;
                    if (sum >= Mod) sum -= Mod;
                    const std::uint32_t difference =
                        even >= odd ? even - odd : even + Mod - odd;
                    values[left + i] = sum;
                    values[left + i + half] = difference;
                    power = power * root % Mod;
                }
            }
            if (length == size) break;
        }

        if (inverse) {
            const u64 inverse_size = quick_power(size % Mod, Mod - 2, Mod);
            for (std::uint32_t& value : values) {
                value = static_cast<std::uint32_t>(static_cast<u64>(value) *
                                                   inverse_size % Mod);
            }
        }
    }

    template <typename A, typename B>
    static std::vector<std::uint32_t> convolution(const std::vector<A>& a,
                                                  const std::vector<B>& b) {
        static_assert(
            detail::is_coefficient_v<A> && detail::is_coefficient_v<B>,
            "polynomial coefficients must be <= 64-bit integers");
        const std::size_t result_size =
            detail::convolution_size(a.size(), b.size());
        if (result_size == 0) return {};
        const std::size_t size = detail::transform_size(result_size);
        if (size > max_length) {
            throw std::length_error("NTT convolution is too long");
        }

        std::vector<std::uint32_t> fa(size), fb(size);
        for (std::size_t i = 0; i < a.size(); ++i) {
            fa[i] =
                static_cast<std::uint32_t>(detail::normalize_mod(a[i], Mod));
        }
        for (std::size_t i = 0; i < b.size(); ++i) {
            fb[i] =
                static_cast<std::uint32_t>(detail::normalize_mod(b[i], Mod));
        }
        transform(fa, false);
        transform(fb, false);
        for (std::size_t i = 0; i < size; ++i) {
            fa[i] = static_cast<std::uint32_t>(static_cast<u64>(fa[i]) * fb[i] %
                                               Mod);
        }
        transform(fa, true);
        fa.resize(result_size);
        return fa;
    }
};

using NTT998244353 = NTT<998'244'353U, 3U, 23>;

template <typename A, typename B>
std::vector<std::uint32_t> convolution_ntt(const std::vector<A>& a,
                                           const std::vector<B>& b) {
    return NTT998244353::convolution(a, b);
}

namespace detail {

constexpr std::uint32_t MTT_P1 = 167'772'161U;
constexpr std::uint32_t MTT_P2 = 469'762'049U;
constexpr std::uint32_t MTT_P3 = 1'224'736'769U;
constexpr std::uint32_t MTT_INV_P1_MOD_P2 = 104'391'568U;
constexpr std::uint32_t MTT_INV_P1P2_MOD_P3 = 721'017'874U;
constexpr u64 MTT_P1P2 = static_cast<u64>(MTT_P1) * MTT_P2;
constexpr u128 MTT_PRODUCT = static_cast<u128>(MTT_P1P2) * MTT_P3;
constexpr u64 MTT_MAX_MODULUS = 2'147'483'647ULL;
constexpr std::size_t MTT_MAX_LENGTH = std::size_t{1} << 24;

using MTTN1 = NTT<MTT_P1, 3U, 25>;
using MTTN2 = NTT<MTT_P2, 3U, 26>;
using MTTN3 = NTT<MTT_P3, 3U, 24>;

static_assert(static_cast<u64>(MTT_P1) * MTT_INV_P1_MOD_P2 % MTT_P2 == 1);
static_assert(static_cast<u64>(MTT_P1P2 % MTT_P3) * MTT_INV_P1P2_MOD_P3 %
                  MTT_P3 ==
              1);
static_assert(MTT_PRODUCT > (static_cast<u128>(1) << 23) *
                                (MTT_MAX_MODULUS - 1) * (MTT_MAX_MODULUS - 1));

inline u128 crt_three(std::uint32_t residue1, std::uint32_t residue2,
                      std::uint32_t residue3) {
    u64 step1 =
        (static_cast<u64>(residue2) + MTT_P2 - residue1 % MTT_P2) % MTT_P2;
    step1 = step1 * MTT_INV_P1_MOD_P2 % MTT_P2;
    const u64 value12 =
        static_cast<u64>(residue1) + static_cast<u64>(MTT_P1) * step1;

    u64 step2 =
        (static_cast<u64>(residue3) + MTT_P3 - value12 % MTT_P3) % MTT_P3;
    step2 = step2 * MTT_INV_P1P2_MOD_P3 % MTT_P3;
    return static_cast<u128>(value12) + static_cast<u128>(MTT_P1P2) * step2;
}

}  // namespace detail

// MTT：三组 NTT + CRT，对任意 1 <= modulus <= INT_MAX（不要求质数）
// 精确计算模卷积。公共代数长度上限 2^24；跑满约需 300 MiB 以上内存。
// CRT 全程使用 u128。
template <typename A, typename B>
std::vector<std::uint32_t> convolution_mtt(const std::vector<A>& a,
                                           const std::vector<B>& b,
                                           i64 modulus) {
    static_assert(detail::is_coefficient_v<A> && detail::is_coefficient_v<B>,
                  "polynomial coefficients must be <= 64-bit integers");
    if (modulus <= 0 || static_cast<u64>(modulus) > detail::MTT_MAX_MODULUS) {
        throw std::invalid_argument("MTT requires 1 <= modulus <= INT_MAX");
    }
    const std::size_t result_size =
        detail::convolution_size(a.size(), b.size());
    if (result_size == 0) return {};
    if (modulus == 1) return std::vector<std::uint32_t>(result_size, 0);
    const std::size_t size = detail::transform_size(result_size);
    if (size > detail::MTT_MAX_LENGTH) {
        throw std::length_error("MTT convolution length exceeds 2^24");
    }

    const u64 mod = static_cast<u64>(modulus);
    std::vector<std::uint32_t> normalized_a(a.size());
    std::vector<std::uint32_t> normalized_b(b.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        normalized_a[i] =
            static_cast<std::uint32_t>(detail::normalize_mod(a[i], mod));
    }
    for (std::size_t i = 0; i < b.size(); ++i) {
        normalized_b[i] =
            static_cast<std::uint32_t>(detail::normalize_mod(b[i], mod));
    }

    const auto residue1 =
        detail::MTTN1::convolution(normalized_a, normalized_b);
    const auto residue2 =
        detail::MTTN2::convolution(normalized_a, normalized_b);
    const auto residue3 =
        detail::MTTN3::convolution(normalized_a, normalized_b);

    std::vector<std::uint32_t> result(result_size);
    for (std::size_t i = 0; i < result_size; ++i) {
        result[i] = static_cast<std::uint32_t>(
            detail::crt_three(residue1[i], residue2[i], residue3[i]) % mod);
    }
    return result;
}

// 拆系数 FFT：令 B=ceil(sqrt(modulus))，把 x 拆成 low+B*high。
// 支持任意 1 <= modulus <= INT_MAX（不要求质数），但仍是浮点算法。
// 为控制误差，限制变换长度 <= 2^20，且三个子卷积的粗界 <= 1e15；
// 超出时抛异常，请改用精确的 convolution_mtt。
template <typename A, typename B>
std::vector<std::uint32_t> convolution_split_fft(const std::vector<A>& a,
                                                 const std::vector<B>& b,
                                                 i64 modulus) {
    static_assert(detail::is_coefficient_v<A> && detail::is_coefficient_v<B>,
                  "polynomial coefficients must be <= 64-bit integers");
    if (modulus <= 0 || static_cast<u64>(modulus) > detail::MTT_MAX_MODULUS) {
        throw std::invalid_argument(
            "split FFT requires 1 <= modulus <= INT_MAX");
    }
    const std::size_t result_size =
        detail::convolution_size(a.size(), b.size());
    if (result_size == 0) return {};
    if (modulus == 1) return std::vector<std::uint32_t>(result_size, 0);
    const std::size_t size = detail::transform_size(result_size);
    if (size > detail::FFT_SAFE_MAX_LENGTH) {
        throw std::length_error("split FFT length exceeds safe limit; use MTT");
    }

    const u64 mod = static_cast<u64>(modulus);
    const u64 base = detail::ceil_sqrt(mod);
    u64 max_a_low = 0, max_a_high = 0;
    u64 max_b_low = 0, max_b_high = 0;
    std::vector<FFTComplex> fa(size), fb(size);
    for (std::size_t i = 0; i < a.size(); ++i) {
        const u64 value = detail::normalize_mod(a[i], mod);
        const u64 low = value % base;
        const u64 high = value / base;
        max_a_low = std::max(max_a_low, low);
        max_a_high = std::max(max_a_high, high);
        fa[i] =
            FFTComplex(static_cast<FFTReal>(low), static_cast<FFTReal>(high));
    }
    for (std::size_t i = 0; i < b.size(); ++i) {
        const u64 value = detail::normalize_mod(b[i], mod);
        const u64 low = value % base;
        const u64 high = value / base;
        max_b_low = std::max(max_b_low, low);
        max_b_high = std::max(max_b_high, high);
        fb[i] =
            FFTComplex(static_cast<FFTReal>(low), static_cast<FFTReal>(high));
    }

    const u128 terms = static_cast<u128>(std::min(a.size(), b.size()));
    const u128 bound_low = terms * max_a_low * max_b_low;
    const u128 bound_high = terms * max_a_high * max_b_high;
    const u128 bound_cross =
        terms * (static_cast<u128>(max_a_low) * max_b_high +
                 static_cast<u128>(max_a_high) * max_b_low);
    if (bound_low > detail::FFT_SAFE_INTEGER_BOUND ||
        bound_high > detail::FFT_SAFE_INTEGER_BOUND ||
        bound_cross > detail::FFT_SAFE_INTEGER_BOUND) {
        throw std::overflow_error(
            "split FFT precision bound exceeded; use MTT");
    }

    fft(fa, false);
    fft(fb, false);
    const FFTComplex minus_half_i(0, -0.5L);
    const FFTComplex plus_i(0, 1);
    for (std::size_t i = 0; i < size; ++i) {
        const std::size_t mirror = (size - i) & (size - 1);
        if (i > mirror) continue;

        const FFTComplex a_low = (fa[i] + std::conj(fa[mirror])) * 0.5L;
        const FFTComplex a_high =
            (fa[i] - std::conj(fa[mirror])) * minus_half_i;
        const FFTComplex b_low = (fb[i] + std::conj(fb[mirror])) * 0.5L;
        const FFTComplex b_high =
            (fb[i] - std::conj(fb[mirror])) * minus_half_i;
        const FFTComplex low_product = a_low * b_low;
        const FFTComplex high_product = a_high * b_high;
        const FFTComplex cross_product = a_low * b_high + a_high * b_low;

        fa[i] = low_product + plus_i * high_product;
        fb[i] = cross_product;
        if (i != mirror) {
            fa[mirror] =
                std::conj(low_product) + plus_i * std::conj(high_product);
            fb[mirror] = std::conj(cross_product);
        }
    }
    fft(fa, true);
    fft(fb, true);

    std::vector<std::uint32_t> result(result_size);
    for (std::size_t i = 0; i < result_size; ++i) {
        const i64 low = detail::round_to_i64(fa[i].real());
        const i64 high = detail::round_to_i64(fa[i].imag());
        const i64 cross = detail::round_to_i64(fb[i].real());
        i128 value = static_cast<i128>(low) + static_cast<i128>(cross) * base +
                     static_cast<i128>(high) * base * base;
        value %= static_cast<i128>(mod);
        if (value < 0) value += static_cast<i128>(mod);
        result[i] = static_cast<std::uint32_t>(value);
    }
    return result;
}

// 位运算卷积：OR/AND/XOR FWT，以及子集格上的快速 Zeta/Möbius 变换。
// 原地变换为 O(n log n)、额外空间 O(1)；n 必须为 2 的幂。
enum class FWTType { Or, And, Xor };

namespace detail {

inline u64 checked_fwt_modulus(i64 modulus) {
    if (modulus <= 0) {
        throw std::invalid_argument("FWT/FMT modulus must be positive");
    }
    return static_cast<u64>(modulus);
}

inline void require_fwt_type(FWTType type) {
    if (type != FWTType::Or && type != FWTType::And && type != FWTType::Xor) {
        throw std::invalid_argument("unknown FWT type");
    }
}

inline int mask_bits(std::size_t size) {
    if (size == 0) return 0;
    if ((size & (size - 1)) != 0) {
        throw std::invalid_argument("FWT/FMT length must be a power of two");
    }
    int bits = 0;
    while (size > 1) {
        size >>= 1;
        ++bits;
    }
    return bits;
}

inline int require_same_mask_shape(std::size_t a_size, std::size_t b_size) {
    if (a_size != b_size) {
        throw std::invalid_argument(
            "bitmask convolution inputs must have equal length");
    }
    return mask_bits(a_size);
}

inline u64 add_mod(u64 a, u64 b, u64 modulus) noexcept {
    assert(a < modulus && b < modulus);
    return a >= modulus - b ? a - (modulus - b) : a + b;
}

inline u64 sub_mod(u64 a, u64 b, u64 modulus) noexcept {
    assert(a < modulus && b < modulus);
    return a >= b ? a - b : modulus - (b - a);
}

inline void require_xor_inverse(std::size_t size, FWTType type, u64 modulus) {
    if (type == FWTType::Xor && size > 1 && (modulus & 1) == 0) {
        throw std::invalid_argument(
            "inverse XOR FWT requires an odd modulus when length > 1");
    }
}

}  // namespace detail

// 原地 FWT。values 是 u64，会先按 modulus 归一化；参数错误时不修改。
// OR/AND 在任意正模下均可逆；XOR 长度 > 1 时逆变换要求奇数模。
inline void fwt(std::vector<u64>& values, FWTType type, bool inverse,
                i64 modulus) {
    const u64 mod = detail::checked_fwt_modulus(modulus);
    detail::require_fwt_type(type);
    const int bits = detail::mask_bits(values.size());
    if (inverse) detail::require_xor_inverse(values.size(), type, mod);

    for (u64& value : values) value %= mod;
    if (values.empty()) return;

    for (std::size_t half = 1; half < values.size(); half <<= 1) {
        for (std::size_t left = 0; left < values.size(); left += half << 1) {
            for (std::size_t i = 0; i < half; ++i) {
                u64& lower = values[left + i];
                u64& upper = values[left + i + half];
                if (type == FWTType::Or) {
                    upper = inverse ? detail::sub_mod(upper, lower, mod)
                                    : detail::add_mod(upper, lower, mod);
                } else if (type == FWTType::And) {
                    lower = inverse ? detail::sub_mod(lower, upper, mod)
                                    : detail::add_mod(lower, upper, mod);
                } else {
                    const u64 sum = detail::add_mod(lower, upper, mod);
                    const u64 difference = detail::sub_mod(lower, upper, mod);
                    lower = sum;
                    upper = difference;
                }
            }
        }
    }

    if (type == FWTType::Xor && inverse && bits > 0) {
        const u64 inverse_two = mod / 2 + 1;
        u64 inverse_size = 1 % mod;
        for (int i = 0; i < bits; ++i) {
            inverse_size = ::mul_mod(inverse_size, inverse_two, mod);
        }
        for (u64& value : values) {
            value = ::mul_mod(value, inverse_size, mod);
        }
    }
}

inline void fwt_or(std::vector<u64>& values, bool inverse, i64 modulus) {
    fwt(values, FWTType::Or, inverse, modulus);
}

inline void fwt_and(std::vector<u64>& values, bool inverse, i64 modulus) {
    fwt(values, FWTType::And, inverse, modulus);
}

inline void fwt_xor(std::vector<u64>& values, bool inverse, i64 modulus) {
    fwt(values, FWTType::Xor, inverse, modulus);
}

// FMT 语义别名：
// subset zeta:   f[S] <- sum_{T subseteq S} f[T]
// superset zeta: f[S] <- sum_{T supseteq S} f[T]
// Möbius 变换分别是二者的逆变换。
inline void subset_zeta_transform(std::vector<u64>& values, i64 modulus) {
    fwt_or(values, false, modulus);
}

inline void subset_mobius_transform(std::vector<u64>& values, i64 modulus) {
    fwt_or(values, true, modulus);
}

inline void superset_zeta_transform(std::vector<u64>& values, i64 modulus) {
    fwt_and(values, false, modulus);
}

inline void superset_mobius_transform(std::vector<u64>& values, i64 modulus) {
    fwt_and(values, true, modulus);
}

// FWT 位运算卷积。两组输入必须等长，长度必须是 2 的幂；返回同样长度。
// 卷积包装支持不超过 64 位的有/无符号整数，并正确归一化负数。
template <typename A, typename B>
std::vector<u64> convolution_fwt(const std::vector<A>& a,
                                 const std::vector<B>& b, FWTType type,
                                 i64 modulus) {
    static_assert(detail::is_coefficient_v<A> && detail::is_coefficient_v<B>,
                  "bitmask coefficients must be <= 64-bit integers");
    const u64 mod = detail::checked_fwt_modulus(modulus);
    detail::require_fwt_type(type);
    detail::require_same_mask_shape(a.size(), b.size());
    detail::require_xor_inverse(a.size(), type, mod);
    if (a.empty()) return {};
    if (mod == 1) return std::vector<u64>(a.size(), 0);

    std::vector<u64> fa(a.size()), fb(b.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        fa[i] = detail::normalize_mod(a[i], mod);
        fb[i] = detail::normalize_mod(b[i], mod);
    }
    fwt(fa, type, false, modulus);
    fwt(fb, type, false, modulus);
    for (std::size_t i = 0; i < fa.size(); ++i) {
        fa[i] = ::mul_mod(fa[i], fb[i], mod);
    }
    fwt(fa, type, true, modulus);
    return fa;
}

template <typename A, typename B>
std::vector<u64> convolution_fwt_or(const std::vector<A>& a,
                                    const std::vector<B>& b, i64 modulus) {
    return convolution_fwt(a, b, FWTType::Or, modulus);
}

template <typename A, typename B>
std::vector<u64> convolution_fwt_and(const std::vector<A>& a,
                                     const std::vector<B>& b, i64 modulus) {
    return convolution_fwt(a, b, FWTType::And, modulus);
}

template <typename A, typename B>
std::vector<u64> convolution_fwt_xor(const std::vector<A>& a,
                                     const std::vector<B>& b, i64 modulus) {
    return convolution_fwt(a, b, FWTType::Xor, modulus);
}

// 标准子集卷积：result[S] = sum_{T subseteq S} a[T] * b[S\T]。
// 设 n=2^k，复杂度 O(k^2*2^k)，额外空间 O(k*2^k)；任意正模可用。
// 当前 u64 实现 k=20 时约需 350 MiB，需结合题目内存限制使用。
template <typename A, typename B>
std::vector<u64> convolution_subset(const std::vector<A>& a,
                                    const std::vector<B>& b, i64 modulus) {
    static_assert(detail::is_coefficient_v<A> && detail::is_coefficient_v<B>,
                  "subset coefficients must be <= 64-bit integers");
    const u64 mod = detail::checked_fwt_modulus(modulus);
    const int bits = detail::require_same_mask_shape(a.size(), b.size());
    if (a.empty()) return {};
    if (mod == 1) return std::vector<u64>(a.size(), 0);

    std::vector<unsigned char> rank(a.size());
    std::vector<std::vector<u64>> ranked_a(bits + 1,
                                           std::vector<u64>(a.size()));
    std::vector<std::vector<u64>> ranked_b(bits + 1,
                                           std::vector<u64>(a.size()));
    for (std::size_t mask = 0; mask < a.size(); ++mask) {
        rank[mask] = static_cast<unsigned char>(bitop::popcount(mask));
        ranked_a[rank[mask]][mask] = detail::normalize_mod(a[mask], mod);
        ranked_b[rank[mask]][mask] = detail::normalize_mod(b[mask], mod);
    }
    for (int current_rank = 0; current_rank <= bits; ++current_rank) {
        subset_zeta_transform(ranked_a[current_rank], modulus);
        subset_zeta_transform(ranked_b[current_rank], modulus);
    }

    std::vector<u64> result(a.size());
    std::vector<u64> layer(a.size());
    for (int current_rank = 0; current_rank <= bits; ++current_rank) {
        for (std::size_t mask = 0; mask < a.size(); ++mask) {
            u64 value = 0;
            for (int left_rank = 0; left_rank <= current_rank; ++left_rank) {
                const u64 product =
                    ::mul_mod(ranked_a[left_rank][mask],
                              ranked_b[current_rank - left_rank][mask], mod);
                value = detail::add_mod(value, product, mod);
            }
            layer[mask] = value;
        }
        subset_mobius_transform(layer, modulus);
        for (std::size_t mask = 0; mask < a.size(); ++mask) {
            if (rank[mask] == current_rank) result[mask] = layer[mask];
        }
    }
    return result;
}

}  // namespace poly

// 卷积使用示例：
// vll a{1, -2, 3}, b{4, 5};
// auto c1 = poly::convolution_fft(a, b);                 // 普通整数卷积
// auto c2 = poly::convolution_ntt(a, b);                 // 模 998244353
// auto c3 = poly::convolution_mtt(a, b, 1'000'000'007); // 任意正 int 模
// auto c4 = poly::convolution_split_fft(
//     a, b, 1'000'000'007);  // 浮点拆系数；超界时改用 MTT
// // 需要单独做变换时：poly::fft(values, inverse)，或
// // poly::NTT998244353::transform(values, inverse)。

// FWT/FMT 使用示例（位掩码数组必须等长，且长度是 2 的幂）：
// vll f{1, -2, 3, 4}, g{5, 6, -7, 8};
// auto h_or = poly::convolution_fwt_or(f, g, 1'000'000'007);
// auto h_and = poly::convolution_fwt_and(f, g, 1'000'000'007);
// auto h_xor = poly::convolution_fwt_xor(
//     f, g, 1'000'000'007);  // 长度 > 1 时 XOR 逆变换要求奇数模
// auto h_subset = poly::convolution_subset(f, g, 1'000'000'007);
//
// vector<u64> sums{1, 2, 3, 4};
// poly::subset_zeta_transform(sums, 1'000'000'007);
// poly::subset_mobius_transform(sums, 1'000'000'007);  // 恢复原数组
// // 超集版本对应 superset_zeta_transform / superset_mobius_transform。

// 整数 INF 是为加法预留余量的算法哨兵，并不等于类型的真正最大值。
// 若合法答案可能超过它，或要从 INF 继续运算，应按题目约束另行处理。
constexpr int INF32 = std::numeric_limits<int>::max() / 4;
constexpr i64 INF64 = std::numeric_limits<i64>::max() / 4;
constexpr int NINF32 = -INF32;
constexpr i64 NINF64 = -INF64;

// 浮点数的 max() 是最大有限正数，lowest() 是最负的有限数，
// infinity() 才是正无穷。注意 min() 是最小正正规数，不是最负值。
constexpr f32 F32_MAX = std::numeric_limits<f32>::max();
constexpr f32 F32_LOWEST = std::numeric_limits<f32>::lowest();
constexpr f32 INF_F32 = std::numeric_limits<f32>::infinity();
constexpr f64 F64_MAX = std::numeric_limits<f64>::max();
constexpr f64 F64_LOWEST = std::numeric_limits<f64>::lowest();
constexpr f64 INF_F64 = std::numeric_limits<f64>::infinity();
constexpr f80 F80_MAX = std::numeric_limits<f80>::max();
constexpr f80 F80_LOWEST = std::numeric_limits<f80>::lowest();
constexpr f80 INF_F80 = std::numeric_limits<f80>::infinity();

// 浮点误差阈值 EPS 与数值尺度、运算次数有关，应该按题目单独定义。
constexpr ll N = 100'000 + 10;
constexpr i64 MOD = 1'000'000'007LL;
constexpr ll MAXN = 100'000 + 5;

void solve() {}

signed main() {
    ios_base::sync_with_stdio(false);
    cin.tie(nullptr);
    ll T = 1LL;
    // cin >> T;
    while (T--) solve();
    return 0;
}
