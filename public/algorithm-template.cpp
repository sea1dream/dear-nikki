#include <bits/stdc++.h>

#include <boost/multiprecision/cpp_int.hpp>
#include <ext/pb_ds/assoc_container.hpp>
#include <ext/pb_ds/tree_policy.hpp>
using namespace std;

// 面向洛谷 GCC 15.1 / C++23；同时使用 bits、PBDS、__int128 等 GCC 扩展。
#if __cplusplus < 202302L
#error "This template requires C++23 or later."
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
      const u64 address =
          static_cast<u64>(reinterpret_cast<std::uintptr_t>(&now));
      return splitmix64(now ^ address);
    }();
    return value;
  }

  static u64 mix(u64 value) noexcept { return splitmix64(value + seed()); }

  static constexpr u64 combine(u64 first, u64 second) noexcept {
    return splitmix64(
        first ^ (second + 0x9e3779b97f4a7c15ULL + (first << 6) + (first >> 2)));
  }

 public:
  using is_transparent = void;

  template <typename T>
    requires((std::is_integral_v<T> || std::is_enum_v<T>) &&
             sizeof(T) <= sizeof(u64))
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
        seed() ^ (static_cast<u64>(value.size()) + 0x9e3779b97f4a7c15ULL));
    for (const char character : value) {
      const auto byte = static_cast<unsigned char>(character);
      result =
          splitmix64(result ^ (static_cast<u64>(byte) + 0x9e3779b97f4a7c15ULL));
    }
    return static_cast<std::size_t>(result);
  }

  std::size_t operator()(const std::string& value) const noexcept {
    return (*this)(std::string_view(value.data(), value.size()));
  }

  template <typename First, typename Second>
  std::size_t operator()(const std::pair<First, Second>& value) const noexcept {
    const u64 first = static_cast<u64>((*this)(value.first));
    const u64 second = static_cast<u64>((*this)(value.second));
    return static_cast<std::size_t>(combine(first, second));
  }
};

template <typename Key>
using safe_unordered_set =
    std::unordered_set<Key, custom_hash, std::equal_to<>>;

template <typename Key, typename Value>
using safe_unordered_map =
    std::unordered_map<Key, Value, custom_hash, std::equal_to<>>;

template <typename HashTable>
void reserve_hash(HashTable& table, std::size_t expected_size) {
  table.max_load_factor(0.7f);  // 必须先设置负载因子，再 reserve。
  table.reserve(expected_size);
}

// PBDS 顺序统计树（GCC 扩展，洛谷 C++23 可用）
template <typename Key, typename Compare = std::less<Key>>
using ordered_set =
    __gnu_pbds::tree<Key, __gnu_pbds::null_type, Compare,
                     __gnu_pbds::rb_tree_tag,
                     __gnu_pbds::tree_order_statistics_node_update>;

// 支持重复值的顺序统计树。不要用 less_equal 伪造 multiset：
// less_equal 不是严格弱序，会破坏 PBDS 的查找、排名和删除。
template <typename T, typename Compare = std::less<T>>
  requires std::strict_weak_order<Compare, const T&, const T&>
class ordered_multiset {
  using key_type = std::pair<T, u64>;

  struct key_compare {
    [[no_unique_address]] Compare compare;

    bool operator()(const key_type& left, const key_type& right) const {
      if (std::invoke(compare, left.first, right.first)) return true;
      if (std::invoke(compare, right.first, left.first)) return false;
      return left.second < right.second;
    }
  };

  using tree_type = ordered_set<key_type, key_compare>;

 public:
  using size_type = typename tree_type::size_type;
  using value_compare = Compare;

  ordered_multiset()
    requires std::default_initializable<Compare>
      : ordered_multiset(Compare{}) {}

  explicit ordered_multiset(Compare compare)
      : key_compare_{std::move(compare)}, tree_(key_compare_) {}

  [[nodiscard]] bool empty() const { return tree_.empty(); }
  [[nodiscard]] size_type size() const { return tree_.size(); }

  void clear() {
    tree_.clear();
    next_id_ = 0;
  }

  void insert(const T& value) {
    if (next_id_ == std::numeric_limits<u64>::max()) [[unlikely]] {
      throw std::overflow_error("ordered_multiset: insertion id exhausted");
    }
    if (!tree_.insert({value, next_id_}).second) [[unlikely]] {
      throw std::logic_error(
          "ordered_multiset: comparator is not a strict weak ordering");
    }
    ++next_id_;
  }

  // 按 Compare 的等价关系删除任意一个 value；成功时返回 true。
  [[nodiscard]] bool erase_one(const T& value) {
    auto it = tree_.lower_bound({value, 0});
    if (it == tree_.end() || !equivalent(it->first, value)) return false;
    tree_.erase(it);
    return true;
  }

  [[nodiscard]] size_type count_less(const T& value) const {
    return tree_.order_of_key({value, 0});
  }

  [[nodiscard]] size_type count_less_equal(const T& value) const {
    return tree_.order_of_key({value, std::numeric_limits<u64>::max()});
  }

  [[nodiscard]] size_type count(const T& value) const {
    return count_less_equal(value) - count_less(value);
  }

  // 返回第 k 小的值（k 从 0 开始）；越界时返回 nullopt。
  [[nodiscard]] std::optional<T> kth(size_type k) const {
    auto it = tree_.find_by_order(k);
    if (it == tree_.end()) return std::nullopt;
    return it->first;
  }

 private:
  [[nodiscard]] bool equivalent(const T& left, const T& right) const {
    return !std::invoke(key_compare_.compare, left, right) &&
           !std::invoke(key_compare_.compare, right, left);
  }

  key_compare key_compare_;
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

// <bit> 的安全封装（支持不超过 64 位的整数，并统一处理零值语义）
namespace bitop {

template <typename T>
[[nodiscard]] constexpr auto to_unsigned(T x) noexcept {
  using V = std::remove_cv_t<T>;
  static_assert(std::is_integral_v<V> && !std::is_same_v<V, bool>);

  using U = std::make_unsigned_t<V>;
  static_assert(std::numeric_limits<U>::digits <=
                std::numeric_limits<unsigned long long>::digits);
  return static_cast<U>(x);
}

// 二进制中 1 的个数。
template <typename T>
[[nodiscard]] constexpr int popcount(T x) noexcept {
  const auto u = to_unsigned(x);
  return std::popcount(u);
}

// 前导零个数；x == 0 时返回类型位数。
template <typename T>
[[nodiscard]] constexpr int countl_zero(T x) noexcept {
  const auto u = to_unsigned(x);
  return std::countl_zero(u);
}

// 后缀零个数；x == 0 时返回类型位数。
template <typename T>
[[nodiscard]] constexpr int countr_zero(T x) noexcept {
  const auto u = to_unsigned(x);
  return std::countr_zero(u);
}

// 最低位 1 的位置（从 1 开始）；x == 0 时返回 0，等价于 __builtin_ffsll
template <typename T>
[[nodiscard]] constexpr int first_one(T x) noexcept {
  const auto u = to_unsigned(x);
  return u == 0 ? 0 : countr_zero(u) + 1;
}

template <typename T>
[[nodiscard]] constexpr int bit_width(T x) noexcept {
  const auto u = to_unsigned(x);
  return std::bit_width(u);
}

// 最高/最低位 1 的下标（从 0 开始）；x == 0 时返回 -1
template <typename T>
[[nodiscard]] constexpr int msb_index(T x) noexcept {
  return bit_width(x) - 1;
}

template <typename T>
[[nodiscard]] constexpr int lsb_index(T x) noexcept {
  const auto u = to_unsigned(x);
  return u == 0 ? -1 : countr_zero(u);
}

template <typename T>
[[nodiscard]] constexpr bool has_single_bit(T x) noexcept {
  return std::has_single_bit(to_unsigned(x));
}

template <typename T>
[[nodiscard]] constexpr int parity(T x) noexcept {
  return popcount(x) & 1;
}

[[nodiscard]] constexpr uint16_t bswap16(uint16_t x) noexcept {
  return std::byteswap(x);
}

[[nodiscard]] constexpr uint32_t bswap32(uint32_t x) noexcept {
  return std::byteswap(x);
}

[[nodiscard]] constexpr uint64_t bswap64(uint64_t x) noexcept {
  return std::byteswap(x);
}

}  // namespace bitop

// 返回 true 表示发生溢出；result 会被写入转换后的运算结果
namespace checked {

template <typename A, typename B, typename R>
[[nodiscard]] constexpr bool add(A a, B b, R& result) noexcept {
  static_assert(std::is_integral_v<A> && std::is_integral_v<B> &&
                std::is_integral_v<R> && !std::is_same_v<R, bool>);
  return __builtin_add_overflow(a, b, &result);
}

template <typename A, typename B, typename R>
[[nodiscard]] constexpr bool sub(A a, B b, R& result) noexcept {
  static_assert(std::is_integral_v<A> && std::is_integral_v<B> &&
                std::is_integral_v<R> && !std::is_same_v<R, bool>);
  return __builtin_sub_overflow(a, b, &result);
}

template <typename A, typename B, typename R>
[[nodiscard]] constexpr bool mul(A a, B b, R& result) noexcept {
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

#define dbg(...)                                \
  do {                                          \
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

// 随机盐哈希使用示例（C++23 可用 contains；string 支持 string_view 异构查询）：
// safe_unordered_set<i64> seen;
// reserve_hash(seen, n);  // 已知最多插入 n 个元素时，先预留容量。
// seen.insert(x);
// bool exists = seen.contains(x);
// seen.erase(x);
//
// safe_unordered_set<pii> edges;            // pair 可直接作为键
// safe_unordered_set<string> names;         // 可用 names.contains(string_view)
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

// 已验证模数后的热路径内核；仅供本模板内部使用。
namespace mod_arithmetic_detail {

[[nodiscard]] constexpr u64 mul_unchecked(u64 a, u64 b, u64 mod) noexcept {
  return static_cast<u64>(static_cast<u128>(a) * b % mod);
}

[[nodiscard]] constexpr u64 power_unchecked(u64 a, u64 b, u64 mod) noexcept {
  u64 res = 1 % mod;
  a %= mod;
  while (b > 0) {
    if (b & 1) res = mul_unchecked(res, a, mod);
    a = mul_unchecked(a, a, mod);
    b >>= 1;
  }
  return res;
}

}  // namespace mod_arithmetic_detail

// 64 位安全模乘。mod == 0 时抛 invalid_argument；合法路径只有一次分支。
[[nodiscard]] constexpr u64 mul_mod(u64 a, u64 b, u64 mod) {
  if (mod == 0) [[unlikely]] {
    throw std::invalid_argument("mul_mod: modulus must be non-zero");
  }
  return mod_arithmetic_detail::mul_unchecked(a, b, mod);
}

// 快速幂计算 (a^b) % mod。mod == 0 时抛 invalid_argument。
// 参数使用 u64，乘法使用 u128 中间值，支持完整 u64 范围；循环内不重复检查。
[[nodiscard]] constexpr u64 quick_power(u64 a, u64 b, u64 mod) {
  if (mod == 0) [[unlikely]] {
    throw std::invalid_argument("quick_power: modulus must be non-zero");
  }
  return mod_arithmetic_detail::power_unchecked(a, b, mod);
}

// 确定性 Miller-Rabin 素性测试，适用于完整 u64 范围。
// 复杂度 O(7 log n)，基底集合不能随意删减。
[[nodiscard]] bool miller_rabin(u64 n) noexcept {
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
    u64 x = mod_arithmetic_detail::power_unchecked(a, d, n);
    if (x == 1 || x == n - 1) continue;

    bool reached_minus_one = false;
    for (int r = 1; r < s; r++) {
      x = mod_arithmetic_detail::mul_unchecked(x, x, n);
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
// ensure(n) 单次最坏 O(n)；对单调增大的 n，总计算量摊还 O(max_n)，查询 O(1)。
// P/C 的阶乘表公式要求 0 <= n < modulus；n >= modulus 时应按题使用
// Lucas 定理或其他算法，不能继续套用阶乘与逆阶乘公式。
// 构造时会验证模数；不满足条件会抛出 invalid_argument/out_of_range。
// 两张表的有效数据占 16 * (prepared() + 1) 字节，实际容量可能略大。
class PrimeComb {
 public:
  explicit PrimeComb(u64 modulus, u64 initial_n = 0)
      : modulus_(modulus), factorial_{1}, inverse_factorial_{1} {
    if (!miller_rabin(modulus_)) {
      throw std::invalid_argument("PrimeComb: modulus must be prime");
    }
    ensure(initial_n);
  }

  [[nodiscard]] u64 modulus() const noexcept { return modulus_; }

  [[nodiscard]] u64 prepared() const noexcept {
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
    const size_t required_size = target + 1;

    // 先让两张表都取得足够容量，再同时改变 size。第二次 reserve 即使抛出，
    // 两张表的有效长度和内容仍保持一致；之后对 u64 的 resize 不再分配内存。
    reserve_tables(required_size);
    factorial_.resize(required_size);
    inverse_factorial_.resize(required_size);

    for (size_t i = old_size; i <= target; ++i) {
      const u64 x = static_cast<u64>(i);
      u64 inverse_x = 1;

      if (x > 1) {
        // modulus = q*x + r，可推出 inv(x) = -q*inv(r)。
        const u64 remainder = modulus_ % x;
        assert(remainder != 0);

        // inv(r) = (r-1)! / r!
        const size_t r = static_cast<size_t>(remainder);
        const u64 inverse_r = mod_arithmetic_detail::mul_unchecked(
            factorial_[r - 1], inverse_factorial_[r], modulus_);
        const u64 term = mod_arithmetic_detail::mul_unchecked(
            modulus_ / x, inverse_r, modulus_);
        assert(term != 0);
        inverse_x = modulus_ - term;
      }

      factorial_[i] =
          mod_arithmetic_detail::mul_unchecked(factorial_[i - 1], x, modulus_);
      inverse_factorial_[i] = mod_arithmetic_detail::mul_unchecked(
          inverse_factorial_[i - 1], inverse_x, modulus_);
    }
  }

  // 返回 n! mod modulus。n >= modulus 时结果必为 0。
  [[nodiscard]] u64 factorial(u64 n) {
    if (n >= modulus_) return 0;
    ensure(n);
    return factorial_[static_cast<size_t>(n)];
  }

  // 返回 (n!)^(-1) mod modulus；仅在 n < modulus 时存在。
  [[nodiscard]] u64 inverse_factorial(u64 n) {
    ensure(n);
    return inverse_factorial_[static_cast<size_t>(n)];
  }

  // P(n, k) = n! / (n-k)!
  [[nodiscard]] u64 P(u64 n, u64 k) {
    if (k > n) return 0;
    ensure(n);

    const size_t nn = static_cast<size_t>(n);
    const size_t nk = static_cast<size_t>(n - k);
    return mod_arithmetic_detail::mul_unchecked(
        factorial_[nn], inverse_factorial_[nk], modulus_);
  }

  // C(n, k) = n! / (k!(n-k)!)
  [[nodiscard]] u64 C(u64 n, u64 k) {
    if (k > n) return 0;
    ensure(n);

    const size_t nn = static_cast<size_t>(n);
    const size_t kk = static_cast<size_t>(k);
    const size_t nk = static_cast<size_t>(n - k);
    const u64 denominator = mod_arithmetic_detail::mul_unchecked(
        inverse_factorial_[kk], inverse_factorial_[nk], modulus_);
    return mod_arithmetic_detail::mul_unchecked(factorial_[nn], denominator,
                                                modulus_);
  }

 private:
  void reserve_tables(size_t required_size) {
    const size_t max_capacity =
        std::min(factorial_.max_size(), inverse_factorial_.max_size());
    if (required_size > max_capacity) {
      throw std::length_error("PrimeComb: table is too large");
    }
    if (factorial_.capacity() >= required_size &&
        inverse_factorial_.capacity() >= required_size) {
      return;
    }

    const size_t current_capacity =
        std::max(factorial_.capacity(), inverse_factorial_.capacity());
    size_t new_capacity = current_capacity;
    if (new_capacity < required_size) {
      const size_t increment = std::max(new_capacity / 2, size_t{1});
      new_capacity = increment <= max_capacity - new_capacity
                         ? new_capacity + increment
                         : max_capacity;
      new_capacity = std::max(new_capacity, required_size);
    }

    factorial_.reserve(new_capacity);
    inverse_factorial_.reserve(new_capacity);
  }

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

inline size_t checked_divisibility_transform(std::span<const i64> values,
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
  if (table.limit < 0 || static_cast<size_t>(table.limit) < n ||
      table.mu.size() <= n || table.mertens.size() <= n) {
    throw std::out_of_range(
        "divisibility transform: Mobius table is too small");
  }
  return n;
}

inline void normalize_from_one(std::span<i64> values, i64 modulus) noexcept {
  for (size_t i = 1; i < values.size(); ++i) {
    values[i] = normalize_i64_mod(values[i], modulus);
  }
}

}  // namespace detail

// 下列四种变换只处理下标 1..n，values[0] 是占位符且保持不变。
// 任意正 i64 模数均可（包括 1、偶数和合数）；单次复杂度
// sum_{p<=n} floor(n/p) = O(n log log n)，额外空间 O(1)。

// F[x] = sum_{d|x} f[d]。
inline void divisor_zeta_transform(std::span<i64> values,
                                   const MobiusTable& table, i64 modulus) {
  const size_t n =
      detail::checked_divisibility_transform(values, table, modulus);
  detail::normalize_from_one(values, modulus);
  for (int prime : table.primes) {
    const size_t p = static_cast<size_t>(prime);
    if (p > n) break;
    for (size_t i = 1, end = n / p; i <= end; ++i) {
      values[i * p] = detail::add_mod(values[i * p], values[i], modulus);
    }
  }
}

// f[x] = sum_{d|x} mu[d] * F[x/d]，是 divisor_zeta_transform 的逆。
inline void divisor_mobius_transform(std::span<i64> values,
                                     const MobiusTable& table, i64 modulus) {
  const size_t n =
      detail::checked_divisibility_transform(values, table, modulus);
  detail::normalize_from_one(values, modulus);
  for (int prime : table.primes) {
    const size_t p = static_cast<size_t>(prime);
    if (p > n) break;
    for (size_t i = n / p; i > 0; --i) {
      values[i * p] = detail::sub_mod(values[i * p], values[i], modulus);
    }
  }
}

// F[x] = sum_{x|multiple, multiple<=n} f[multiple]。
inline void multiple_zeta_transform(std::span<i64> values,
                                    const MobiusTable& table, i64 modulus) {
  const size_t n =
      detail::checked_divisibility_transform(values, table, modulus);
  detail::normalize_from_one(values, modulus);
  for (int prime : table.primes) {
    const size_t p = static_cast<size_t>(prime);
    if (p > n) break;
    for (size_t i = n / p; i > 0; --i) {
      values[i] = detail::add_mod(values[i], values[i * p], modulus);
    }
  }
}

// f[x] = sum_{k<=n/x} mu[k] * F[x*k]，是 multiple_zeta_transform 的逆。
inline void multiple_mobius_transform(std::span<i64> values,
                                      const MobiusTable& table, i64 modulus) {
  const size_t n =
      detail::checked_divisibility_transform(values, table, modulus);
  detail::normalize_from_one(values, modulus);
  for (int prime : table.primes) {
    const size_t p = static_cast<size_t>(prime);
    if (p > n) break;
    for (size_t i = 1, end = n / p; i <= end; ++i) {
      values[i] = detail::sub_mod(values[i], values[i * p], modulus);
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
  const u64 product =
      ::mod_arithmetic_detail::mul_unchecked(same, factor, modulus);
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
      row[k] = detail::transition(row[k - 1], row[k], current, k, kind, mod);
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
      current[k] = detail::transition(previous[k - 1], same, n, k, kind, mod);
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

// 稠密矩阵、模矩阵运算、快速幂、行列式、高斯消元、矩阵树和热带半环。
namespace matrix {

// 保留行列数，因此可以准确表示 0*n、n*0 和 0*0 矩阵。
template <typename T>
class DenseMatrix {
  static_assert(!std::is_same_v<std::remove_cv_t<T>, bool>,
                "DenseMatrix<bool> is not supported");

 public:
  using value_type = T;
  using storage_type = std::vector<T>;

  // 连续存储；行视图允许修改元素，但不暴露 resize/clear，因而不会破坏形状。
  class RowView {
   public:
    explicit RowView(std::span<T> row) noexcept : row_(row) {}
    RowView(const RowView&) noexcept = default;
    RowView& operator=(const RowView&) = delete;

    T& operator[](size_t column) const noexcept { return row_[column]; }
    T& at(size_t column) const {
      if (column >= row_.size()) {
        throw std::out_of_range("matrix column is out of range");
      }
      return row_[column];
    }
    auto begin() const noexcept { return row_.begin(); }
    auto end() const noexcept { return row_.end(); }
    [[nodiscard]] size_t size() const noexcept { return row_.size(); }
    [[nodiscard]] operator std::span<T>() const noexcept { return row_; }

   private:
    std::span<T> row_;
  };

  class ConstRowView {
   public:
    explicit ConstRowView(std::span<const T> row) noexcept : row_(row) {}
    ConstRowView(const ConstRowView&) noexcept = default;
    ConstRowView& operator=(const ConstRowView&) = delete;

    const T& operator[](size_t column) const noexcept { return row_[column]; }
    const T& at(size_t column) const {
      if (column >= row_.size()) {
        throw std::out_of_range("matrix column is out of range");
      }
      return row_[column];
    }
    auto begin() const noexcept { return row_.begin(); }
    auto end() const noexcept { return row_.end(); }
    [[nodiscard]] size_t size() const noexcept { return row_.size(); }
    [[nodiscard]] operator std::span<const T>() const noexcept { return row_; }

   private:
    std::span<const T> row_;
  };

  DenseMatrix() = default;

  DenseMatrix(size_t rows, size_t columns, const T& value = T{})
      : rows_(rows),
        columns_(columns),
        data_(checked_element_count(rows, columns), value) {}

  explicit DenseMatrix(vector<vector<T>> values)
      : rows_(values.size()),
        columns_(values.empty() ? 0 : values.front().size()) {
    for (const auto& row : values) {
      if (row.size() != columns_) {
        throw std::invalid_argument("DenseMatrix rows must have equal length");
      }
    }
    data_.reserve(checked_element_count(rows_, columns_));
    for (auto& row : values) {
      data_.insert(data_.end(), std::make_move_iterator(row.begin()),
                   std::make_move_iterator(row.end()));
    }
  }

  DenseMatrix(std::initializer_list<std::initializer_list<T>> values)
      : rows_(values.size()),
        columns_(values.size() == 0 ? 0 : values.begin()->size()) {
    data_.reserve(checked_element_count(rows_, columns_));
    for (const auto& row : values) {
      if (row.size() != columns_) {
        throw std::invalid_argument("DenseMatrix rows must have equal length");
      }
      data_.insert(data_.end(), row.begin(), row.end());
    }
  }

  [[nodiscard]] size_t rows() const noexcept { return rows_; }
  [[nodiscard]] size_t columns() const noexcept { return columns_; }
  [[nodiscard]] bool empty() const noexcept {
    return rows_ == 0 || columns_ == 0;
  }

  [[nodiscard]] RowView row(size_t index) noexcept {
    return RowView(std::span<T>(data_).subspan(index * columns_, columns_));
  }
  [[nodiscard]] ConstRowView row(size_t index) const noexcept {
    return ConstRowView(
        std::span<const T>(data_).subspan(index * columns_, columns_));
  }
  [[nodiscard]] RowView operator[](size_t index) noexcept { return row(index); }
  [[nodiscard]] ConstRowView operator[](size_t index) const noexcept {
    return row(index);
  }

  T& at(size_t row_index, size_t column) {
    if (row_index >= rows_ || column >= columns_) {
      throw std::out_of_range("matrix index is out of range");
    }
    return data_[row_index * columns_ + column];
  }
  const T& at(size_t row_index, size_t column) const {
    if (row_index >= rows_ || column >= columns_) {
      throw std::out_of_range("matrix index is out of range");
    }
    return data_[row_index * columns_ + column];
  }

  // data() 现在是按行连续的一维存储；row()/operator[] 提供二维访问。
  [[nodiscard]] const storage_type& data() const noexcept { return data_; }
  [[nodiscard]] std::span<T> flat_data() noexcept { return data_; }
  [[nodiscard]] std::span<const T> flat_data() const noexcept { return data_; }

  void swap_rows(size_t first, size_t second) {
    if (first >= rows_ || second >= rows_) {
      throw std::out_of_range("matrix row is out of range");
    }
    if (first != second) {
      std::ranges::swap_ranges(row(first), row(second));
    }
  }

  friend bool operator==(const DenseMatrix& left, const DenseMatrix& right) {
    return left.rows_ == right.rows_ && left.columns_ == right.columns_ &&
           left.data_ == right.data_;
  }

  friend bool operator!=(const DenseMatrix& left, const DenseMatrix& right) {
    return !(left == right);
  }

 private:
  static size_t checked_element_count(size_t rows, size_t columns) {
    if (columns != 0 && rows > std::numeric_limits<size_t>::max() / columns) {
      throw std::length_error("matrix element count overflows size_t");
    }
    return rows * columns;
  }

  size_t rows_ = 0;
  size_t columns_ = 0;
  storage_type data_;
};

namespace detail {

template <typename T>
concept MatrixInteger =
    std::integral<std::remove_cv_t<T>> &&
    (!std::same_as<std::remove_cv_t<T>, bool>) && (sizeof(T) <= sizeof(u64));

template <typename T>
concept MatrixExponent = MatrixInteger<T>;

template <typename T>
inline void require_same_shape(const DenseMatrix<T>& left,
                               const DenseMatrix<T>& right) {
  if (left.rows() != right.rows() || left.columns() != right.columns()) {
    throw std::invalid_argument("matrix dimensions do not match");
  }
}

template <typename Left, typename Right>
inline void require_multipliable(const DenseMatrix<Left>& left,
                                 const DenseMatrix<Right>& right) {
  if (left.columns() != right.rows()) {
    throw std::invalid_argument(
        "matrix multiplication dimensions do not match");
  }
}

template <typename T>
inline void require_square(const DenseMatrix<T>& value) {
  if (value.rows() != value.columns()) {
    throw std::invalid_argument("matrix must be square");
  }
}

inline void require_modulus(u64 modulus) {
  if (modulus == 0) {
    throw std::invalid_argument("matrix modulus must be non-zero");
  }
}

inline void require_prime_modulus(u64 modulus) {
  if (!::miller_rabin(modulus)) {
    throw std::invalid_argument("matrix modulus must be prime");
  }
}

template <MatrixExponent Exponent>
constexpr u64 checked_exponent(Exponent exponent) {
  using Value = std::remove_cv_t<Exponent>;
  if constexpr (std::is_signed_v<Value>) {
    if (exponent < 0) {
      throw std::invalid_argument("matrix exponent must be non-negative");
    }
  }
  return static_cast<u64>(exponent);
}

constexpr u64 normalize_mod_value(u64 value, u64 modulus) noexcept {
  assert(modulus != 0);
  return value % modulus;
}

constexpr u64 normalize_mod_value(i64 value, u64 modulus) noexcept {
  assert(modulus != 0);
  i128 result = static_cast<i128>(value) % static_cast<i128>(modulus);
  if (result < 0) result += static_cast<i128>(modulus);
  return static_cast<u64>(result);
}

constexpr u64 add_mod(u64 left, u64 right, u64 modulus) noexcept {
  assert(left < modulus && right < modulus);
  return left >= modulus - right ? left - (modulus - right) : left + right;
}

constexpr u64 sub_mod(u64 left, u64 right, u64 modulus) noexcept {
  assert(left < modulus && right < modulus);
  return left >= right ? left - right : modulus - (right - left);
}

}  // namespace detail

template <typename T>
[[nodiscard]] DenseMatrix<T> identity(size_t size) {
  DenseMatrix<T> result(size, size);
  for (size_t i = 0; i < size; ++i) result[i][i] = T{1};
  return result;
}

template <typename T>
[[nodiscard]] DenseMatrix<T> transpose(const DenseMatrix<T>& value) {
  DenseMatrix<T> result(value.columns(), value.rows());
  for (size_t row = 0; row < value.rows(); ++row) {
    for (size_t column = 0; column < value.columns(); ++column) {
      result[column][row] = value[row][column];
    }
  }
  return result;
}

// 普通运算直接使用 T 的 +、-、*；整数是否溢出由题目数据范围保证。
template <typename T>
[[nodiscard]] DenseMatrix<T> add(const DenseMatrix<T>& left,
                                 const DenseMatrix<T>& right) {
  detail::require_same_shape(left, right);
  DenseMatrix<T> result(left.rows(), left.columns());
  auto output = result.flat_data();
  const auto left_data = left.flat_data();
  const auto right_data = right.flat_data();
  for (size_t i = 0; i < output.size(); ++i) {
    output[i] = left_data[i] + right_data[i];
  }
  return result;
}

template <typename T>
[[nodiscard]] DenseMatrix<T> subtract(const DenseMatrix<T>& left,
                                      const DenseMatrix<T>& right) {
  detail::require_same_shape(left, right);
  DenseMatrix<T> result(left.rows(), left.columns());
  auto output = result.flat_data();
  const auto left_data = left.flat_data();
  const auto right_data = right.flat_data();
  for (size_t i = 0; i < output.size(); ++i) {
    output[i] = left_data[i] - right_data[i];
  }
  return result;
}

template <typename T>
[[nodiscard]] DenseMatrix<T> multiply(const DenseMatrix<T>& left,
                                      const DenseMatrix<T>& right) {
  detail::require_multipliable(left, right);
  DenseMatrix<T> result(left.rows(), right.columns());
  for (size_t row = 0; row < left.rows(); ++row) {
    auto output = result[row];
    const auto left_row = left[row];
    for (size_t middle = 0; middle < left.columns(); ++middle) {
      const auto right_row = right[middle];
      for (size_t column = 0; column < right.columns(); ++column) {
        output[column] = output[column] + left_row[middle] * right_row[column];
      }
    }
  }
  return result;
}

template <typename T>
[[nodiscard]] vector<T> multiply_vector(const DenseMatrix<T>& left,
                                        std::span<const T> right) {
  if (left.columns() != right.size()) {
    throw std::invalid_argument("matrix-vector dimensions do not match");
  }
  vector<T> result(left.rows());
  for (size_t row = 0; row < left.rows(); ++row) {
    const auto left_row = left[row];
    for (size_t column = 0; column < left.columns(); ++column) {
      result[row] = result[row] + left_row[column] * right[column];
    }
  }
  return result;
}

template <typename T, detail::MatrixExponent Exponent>
[[nodiscard]] DenseMatrix<T> power(DenseMatrix<T> base, Exponent exponent) {
  detail::require_square(base);
  u64 remaining = detail::checked_exponent(exponent);
  DenseMatrix<T> result = identity<T>(base.rows());
  while (remaining > 0) {
    if (remaining & 1) result = multiply(result, base);
    remaining >>= 1;
    if (remaining > 0) base = multiply(base, base);
  }
  return result;
}

[[nodiscard]] inline DenseMatrix<u64> normalize_mod_matrix(
    DenseMatrix<u64> value, u64 modulus) {
  detail::require_modulus(modulus);
  for (u64& element : value.flat_data()) element %= modulus;
  return value;
}

[[nodiscard]] inline DenseMatrix<u64> normalize_mod_matrix(
    const DenseMatrix<i64>& value, u64 modulus) {
  detail::require_modulus(modulus);
  DenseMatrix<u64> result(value.rows(), value.columns());
  auto output = result.flat_data();
  const auto input = value.flat_data();
  for (size_t i = 0; i < output.size(); ++i) {
    output[i] = detail::normalize_mod_value(input[i], modulus);
  }
  return result;
}

[[nodiscard]] inline DenseMatrix<u64> identity_mod(size_t size, u64 modulus) {
  detail::require_modulus(modulus);
  DenseMatrix<u64> result(size, size);
  for (size_t i = 0; i < size; ++i) result[i][i] = 1 % modulus;
  return result;
}

[[nodiscard]] inline DenseMatrix<u64> add_mod(const DenseMatrix<u64>& left,
                                              const DenseMatrix<u64>& right,
                                              u64 modulus) {
  detail::require_modulus(modulus);
  detail::require_same_shape(left, right);
  DenseMatrix<u64> result(left.rows(), left.columns());
  auto output = result.flat_data();
  const auto left_data = left.flat_data();
  const auto right_data = right.flat_data();
  for (size_t i = 0; i < output.size(); ++i) {
    const u64 a = left_data[i] % modulus;
    const u64 b = right_data[i] % modulus;
    output[i] = detail::add_mod(a, b, modulus);
  }
  return result;
}

[[nodiscard]] inline DenseMatrix<u64> subtract_mod(
    const DenseMatrix<u64>& left, const DenseMatrix<u64>& right, u64 modulus) {
  detail::require_modulus(modulus);
  detail::require_same_shape(left, right);
  DenseMatrix<u64> result(left.rows(), left.columns());
  auto output = result.flat_data();
  const auto left_data = left.flat_data();
  const auto right_data = right.flat_data();
  for (size_t i = 0; i < output.size(); ++i) {
    const u64 a = left_data[i] % modulus;
    const u64 b = right_data[i] % modulus;
    output[i] = detail::sub_mod(a, b, modulus);
  }
  return result;
}

// 使用全局 u128 模乘，支持完整非零 u64 模数。
[[nodiscard]] inline DenseMatrix<u64> multiply_mod(
    const DenseMatrix<u64>& left, const DenseMatrix<u64>& right, u64 modulus) {
  detail::require_modulus(modulus);
  detail::require_multipliable(left, right);
  const DenseMatrix<u64> normalized_right =
      normalize_mod_matrix(DenseMatrix<u64>(right), modulus);
  DenseMatrix<u64> result(left.rows(), right.columns());
  for (size_t row = 0; row < left.rows(); ++row) {
    auto output = result[row];
    const auto left_row = left[row];
    for (size_t middle = 0; middle < left.columns(); ++middle) {
      const u64 a = left_row[middle] % modulus;
      if (a == 0) continue;
      const auto right_row = normalized_right[middle];
      for (size_t column = 0; column < right.columns(); ++column) {
        const u64 b = right_row[column];
        const u64 product = ::mul_mod(a, b, modulus);
        output[column] = detail::add_mod(output[column], product, modulus);
      }
    }
  }
  return result;
}

[[nodiscard]] inline vector<u64> multiply_vector_mod(
    const DenseMatrix<u64>& left, std::span<const u64> right, u64 modulus) {
  detail::require_modulus(modulus);
  if (left.columns() != right.size()) {
    throw std::invalid_argument("matrix-vector dimensions do not match");
  }
  vector<u64> normalized_right(right.size());
  for (size_t i = 0; i < right.size(); ++i) {
    normalized_right[i] = right[i] % modulus;
  }
  vector<u64> result(left.rows());
  for (size_t row = 0; row < left.rows(); ++row) {
    const auto left_row = left[row];
    for (size_t column = 0; column < left.columns(); ++column) {
      const u64 product = ::mul_mod(left_row[column] % modulus,
                                    normalized_right[column], modulus);
      result[row] = detail::add_mod(result[row], product, modulus);
    }
  }
  return result;
}

template <detail::MatrixExponent Exponent>
[[nodiscard]] DenseMatrix<u64> power_mod(DenseMatrix<u64> base,
                                         Exponent exponent, u64 modulus) {
  detail::require_modulus(modulus);
  detail::require_square(base);
  u64 remaining = detail::checked_exponent(exponent);
  base = normalize_mod_matrix(std::move(base), modulus);
  DenseMatrix<u64> result = identity_mod(base.rows(), modulus);
  while (remaining > 0) {
    if (remaining & 1) result = multiply_mod(result, base, modulus);
    remaining >>= 1;
    if (remaining > 0) base = multiply_mod(base, base, modulus);
  }
  return result;
}

// 质数模高斯消元求行列式，空矩阵行列式定义为 1。
[[nodiscard]] inline u64 determinant_mod_prime(DenseMatrix<u64> value,
                                               u64 prime_modulus) {
  detail::require_prime_modulus(prime_modulus);
  detail::require_square(value);
  value = normalize_mod_matrix(std::move(value), prime_modulus);

  u64 determinant = 1 % prime_modulus;
  for (size_t column = 0; column < value.rows(); ++column) {
    size_t pivot = column;
    while (pivot < value.rows() && value[pivot][column] == 0) ++pivot;
    if (pivot == value.rows()) return 0;

    if (pivot != column) {
      value.swap_rows(pivot, column);
      determinant = determinant == 0 ? 0 : prime_modulus - determinant;
    }
    const u64 pivot_value = value[column][column];
    determinant = ::mul_mod(determinant, pivot_value, prime_modulus);
    const u64 inverse =
        ::quick_power(pivot_value, prime_modulus - 2, prime_modulus);

    for (size_t row = column + 1; row < value.rows(); ++row) {
      if (value[row][column] == 0) continue;
      const u64 factor = ::mul_mod(value[row][column], inverse, prime_modulus);
      value[row][column] = 0;
      for (size_t next = column + 1; next < value.columns(); ++next) {
        const u64 product =
            ::mul_mod(factor, value[column][next], prime_modulus);
        value[row][next] =
            detail::sub_mod(value[row][next], product, prime_modulus);
      }
    }
  }
  return determinant;
}

enum class LinearSystemStatus { NoSolution, Unique, Infinite };

template <typename T>
struct GaussianResult {
  LinearSystemStatus status;
  size_t rank;         // 系数矩阵的秩。
  vector<T> solution;  // 无解时为空；有解时所有自由变量取 0。
  vector<size_t> pivot_columns;
};

namespace detail {

template <typename T>
inline void require_augmented_shape(const vector<vector<T>>& augmented,
                                    size_t variables) {
  if (variables == std::numeric_limits<size_t>::max()) {
    throw std::length_error("Gaussian elimination matrix is too wide");
  }
  const size_t width = variables + 1;
  for (const auto& row : augmented) {
    if (row.size() != width) {
      throw std::invalid_argument(
          "Gaussian elimination augmented matrix has invalid shape");
    }
  }
}

template <typename Integer>
constexpr u64 normalize_integer_mod(Integer value, u64 modulus) noexcept {
  using Value = std::remove_cv_t<Integer>;
  static_assert(std::is_integral_v<Value> && !std::is_same_v<Value, bool>);
  static_assert(sizeof(Value) <= sizeof(u64));
  if constexpr (std::is_signed_v<Value>) {
    i128 result = static_cast<i128>(value) % static_cast<i128>(modulus);
    if (result < 0) result += static_cast<i128>(modulus);
    return static_cast<u64>(result);
  } else {
    return static_cast<u64>(value) % modulus;
  }
}

}  // namespace detail

// 浮点数值秩：先按每行最大绝对值归一化，再做列主元前向消元。
// epsilon 是相对单行尺度的阈值；病态矩阵的数值秩取决于该阈值。
[[nodiscard]] inline size_t rank_real(
    DenseMatrix<f80> value,
    f80 epsilon = 64 * std::numeric_limits<f80>::epsilon()) {
  if (!std::isfinite(epsilon) || epsilon < 0 || epsilon >= 1) {
    throw std::invalid_argument("rank_real: epsilon must be in [0, 1)");
  }
  for (size_t row = 0; row < value.rows(); ++row) {
    auto current = value[row];
    f80 scale = 0;
    for (const f80 element : current) {
      if (!std::isfinite(element)) {
        throw std::invalid_argument("rank_real: entries must be finite");
      }
      scale = std::max(scale, std::abs(element));
    }
    if (scale != 0) {
      for (f80& element : current) element /= scale;
    }
  }

  size_t rank = 0;
  for (size_t column = 0; column < value.columns() && rank < value.rows();
       ++column) {
    size_t pivot = rank;
    for (size_t row = rank + 1; row < value.rows(); ++row) {
      if (std::abs(value[row][column]) > std::abs(value[pivot][column])) {
        pivot = row;
      }
    }
    if (std::abs(value[pivot][column]) <= epsilon) continue;
    value.swap_rows(pivot, rank);

    const f80 pivot_value = value[rank][column];
    const auto pivot_row = value[rank];
    for (size_t row = rank + 1; row < value.rows(); ++row) {
      auto current = value[row];
      const f80 factor = current[column] / pivot_value;
      current[column] = 0;
      for (size_t next = column + 1; next < value.columns(); ++next) {
        current[next] = std::fma(-factor, pivot_row[next], current[next]);
        if (!std::isfinite(current[next])) {
          throw std::overflow_error("rank_real: non-finite arithmetic");
        }
      }
    }
    ++rank;
  }
  return rank;
}

[[nodiscard]] inline size_t rank_real(
    const vector<vector<f80>>& value,
    f80 epsilon = 64 * std::numeric_limits<f80>::epsilon()) {
  return rank_real(DenseMatrix<f80>(value), epsilon);
}

// 质数模有限域上的精确秩；只做前向消元，不计算 RREF 或方程解。
template <detail::MatrixInteger Integer>
[[nodiscard]] size_t rank_mod_prime(const DenseMatrix<Integer>& input,
                                    u64 prime_modulus) {
  detail::require_prime_modulus(prime_modulus);
  DenseMatrix<u64> value(input.rows(), input.columns());
  const auto source = input.flat_data();
  auto destination = value.flat_data();
  for (size_t i = 0; i < source.size(); ++i) {
    destination[i] = detail::normalize_integer_mod(source[i], prime_modulus);
  }

  size_t rank = 0;
  for (size_t column = 0; column < value.columns() && rank < value.rows();
       ++column) {
    size_t pivot = rank;
    while (pivot < value.rows() && value[pivot][column] == 0) ++pivot;
    if (pivot == value.rows()) continue;
    value.swap_rows(pivot, rank);

    const u64 inverse =
        ::quick_power(value[rank][column], prime_modulus - 2, prime_modulus);
    const auto pivot_row = value[rank];
    for (size_t row = rank + 1; row < value.rows(); ++row) {
      auto current = value[row];
      if (current[column] == 0) continue;
      const u64 factor = ::mul_mod(current[column], inverse, prime_modulus);
      current[column] = 0;
      for (size_t next = column + 1; next < value.columns(); ++next) {
        current[next] = detail::sub_mod(
            current[next], ::mul_mod(factor, pivot_row[next], prime_modulus),
            prime_modulus);
      }
    }
    ++rank;
  }
  return rank;
}

template <detail::MatrixInteger Integer>
[[nodiscard]] size_t rank_mod_prime(const vector<vector<Integer>>& value,
                                    u64 prime_modulus) {
  return rank_mod_prime(DenseMatrix<Integer>(value), prime_modulus);
}

// augmented 每行是 n 个系数和最后一个常数，共 n+1 列。
// 先按每行最大系数缩放，再做绝对值最大主元的 RREF；epsilon 因而是
// 相对于单个方程尺度的阈值。病态问题仍应按数据误差自行调整 epsilon。
// m 个方程、n 个未知量的时间复杂度 O(m*n*min(m,n))。
[[nodiscard]] inline GaussianResult<f80> gaussian_elimination_real(
    vector<vector<f80>> augmented, size_t variables,
    f80 epsilon = 64 * std::numeric_limits<f80>::epsilon()) {
  detail::require_augmented_shape(augmented, variables);
  if (!std::isfinite(epsilon) || epsilon < 0 || epsilon >= 1) {
    throw std::invalid_argument(
        "gaussian_elimination_real: epsilon must be in [0, 1)");
  }

  const size_t rows = augmented.size();
  const size_t no_pivot = std::numeric_limits<size_t>::max();
  vector<size_t> where(variables, no_pivot);
  vector<size_t> pivot_columns;

  for (auto& equation : augmented) {
    f80 scale = 0;
    for (f80 value : equation) {
      if (!std::isfinite(value)) {
        throw std::invalid_argument(
            "gaussian_elimination_real: entries must be finite");
      }
    }
    for (size_t column = 0; column < variables; ++column) {
      scale = std::max(scale, std::abs(equation[column]));
    }

    if (scale != 0) {
      for (f80& value : equation) {
        value /= scale;
        if (!std::isfinite(value)) {
          throw std::overflow_error(
              "gaussian_elimination_real: non-finite arithmetic");
        }
      }
    } else if (equation[variables] != 0) {
      // 精确的 0 = 非零一定无解，不应因 RHS 很小而被 EPS 忽略。
      equation[variables] =
          std::copysign(static_cast<f80>(1), equation[variables]);
    }
  }

  const auto is_zero = [epsilon](f80 value) {
    return std::abs(value) <= epsilon;
  };

  size_t rank = 0;
  for (size_t column = 0; column < variables && rank < rows; ++column) {
    size_t pivot = rank;
    for (size_t row = rank + 1; row < rows; ++row) {
      if (std::abs(augmented[row][column]) >
          std::abs(augmented[pivot][column])) {
        pivot = row;
      }
    }
    if (is_zero(augmented[pivot][column])) continue;

    std::swap(augmented[pivot], augmented[rank]);
    where[column] = rank;
    pivot_columns.push_back(column);

    const f80 pivot_value = augmented[rank][column];
    for (size_t next = column + 1; next <= variables; ++next) {
      augmented[rank][next] /= pivot_value;
      if (!std::isfinite(augmented[rank][next])) {
        throw std::overflow_error(
            "gaussian_elimination_real: non-finite arithmetic");
      }
    }
    augmented[rank][column] = 1;

    for (size_t row = 0; row < rows; ++row) {
      if (row == rank) continue;
      const f80 factor = augmented[row][column];
      if (factor == 0) continue;
      for (size_t next = column + 1; next <= variables; ++next) {
        augmented[row][next] =
            std::fma(-factor, augmented[rank][next], augmented[row][next]);
        if (!std::isfinite(augmented[row][next])) {
          throw std::overflow_error(
              "gaussian_elimination_real: non-finite arithmetic");
        }
      }
      augmented[row][column] = 0;
    }
    ++rank;
  }

  for (const auto& equation : augmented) {
    bool zero_left = true;
    for (size_t column = 0; column < variables; ++column) {
      if (!is_zero(equation[column])) {
        zero_left = false;
        break;
      }
    }
    if (zero_left && !is_zero(equation[variables])) {
      return {
          LinearSystemStatus::NoSolution, rank, {}, std::move(pivot_columns)};
    }
  }

  vector<f80> solution(variables);
  for (size_t column = 0; column < variables; ++column) {
    if (where[column] != no_pivot) {
      solution[column] = augmented[where[column]][variables];
      if (is_zero(solution[column])) solution[column] = 0;
    }
  }
  const LinearSystemStatus status = rank == variables
                                        ? LinearSystemStatus::Unique
                                        : LinearSystemStatus::Infinite;
  return {status, rank, std::move(solution), std::move(pivot_columns)};
}

// 质数模有限域高斯消元。元素可用任意不超过 64 位的非 bool 整数，
// 负数会自动规范化；模数使用完整 u64 Miller-Rabin 验证。
template <detail::MatrixInteger Integer>
[[nodiscard]] GaussianResult<u64> gaussian_elimination_prime_mod(
    const vector<vector<Integer>>& augmented, size_t variables,
    u64 prime_modulus) {
  detail::require_augmented_shape(augmented, variables);
  detail::require_prime_modulus(prime_modulus);

  const size_t rows = augmented.size();
  const size_t width = variables + 1;
  const size_t no_pivot = std::numeric_limits<size_t>::max();
  vector<vector<u64>> value(rows, vector<u64>(width));
  for (size_t row = 0; row < rows; ++row) {
    for (size_t column = 0; column < width; ++column) {
      value[row][column] =
          detail::normalize_integer_mod(augmented[row][column], prime_modulus);
    }
  }

  vector<size_t> where(variables, no_pivot);
  vector<size_t> pivot_columns;
  size_t rank = 0;
  for (size_t column = 0; column < variables && rank < rows; ++column) {
    size_t pivot = rank;
    while (pivot < rows && value[pivot][column] == 0) ++pivot;
    if (pivot == rows) continue;

    std::swap(value[pivot], value[rank]);
    where[column] = rank;
    pivot_columns.push_back(column);
    const u64 inverse =
        ::quick_power(value[rank][column], prime_modulus - 2, prime_modulus);
    for (size_t next = column + 1; next <= variables; ++next) {
      value[rank][next] = ::mul_mod(value[rank][next], inverse, prime_modulus);
    }
    value[rank][column] = 1;

    for (size_t row = 0; row < rows; ++row) {
      if (row == rank) continue;
      const u64 factor = value[row][column];
      if (factor == 0) continue;
      for (size_t next = column + 1; next <= variables; ++next) {
        const u64 product = ::mul_mod(factor, value[rank][next], prime_modulus);
        value[row][next] =
            detail::sub_mod(value[row][next], product, prime_modulus);
      }
      value[row][column] = 0;
    }
    ++rank;
  }

  for (const auto& equation : value) {
    bool zero_left = true;
    for (size_t column = 0; column < variables; ++column) {
      if (equation[column] != 0) {
        zero_left = false;
        break;
      }
    }
    if (zero_left && equation[variables] != 0) {
      return {
          LinearSystemStatus::NoSolution, rank, {}, std::move(pivot_columns)};
    }
  }

  vector<u64> solution(variables);
  for (size_t column = 0; column < variables; ++column) {
    if (where[column] != no_pivot) {
      solution[column] = value[where[column]][variables];
    }
  }
  const LinearSystemStatus status = rank == variables
                                        ? LinearSystemStatus::Unique
                                        : LinearSystemStatus::Infinite;
  return {status, rank, std::move(solution), std::move(pivot_columns)};
}

struct UndirectedEdge {
  size_t u;
  size_t v;
  u64 weight = 1;
};

struct DirectedEdge {
  size_t from;
  size_t to;
  u64 weight = 1;
};

enum class ArborescenceDirection {
  TowardRoot,   // 每个点沿有向边最终走到 root。
  AwayFromRoot  // 从 root 沿有向边可到达每个点。
};

namespace detail {

inline void require_nonempty_graph(size_t vertex_count) {
  if (vertex_count == 0) {
    throw std::invalid_argument(
        "Matrix-Tree theorem requires at least one vertex");
  }
}

inline void require_vertex(size_t vertex, size_t vertex_count) {
  if (vertex >= vertex_count) {
    throw std::out_of_range("graph vertex is out of range");
  }
}

inline void require_direction(ArborescenceDirection direction) {
  if (direction != ArborescenceDirection::TowardRoot &&
      direction != ArborescenceDirection::AwayFromRoot) {
    throw std::invalid_argument("unknown arborescence direction");
  }
}

inline void add_to_cell(u64& cell, u64 value, u64 modulus) noexcept {
  cell = add_mod(cell, value, modulus);
}

inline void subtract_from_cell(u64& cell, u64 value, u64 modulus) noexcept {
  cell = sub_mod(cell, value, modulus);
}

inline DenseMatrix<u64> principal_minor(const DenseMatrix<u64>& value,
                                        size_t removed) {
  require_square(value);
  if (removed >= value.rows()) {
    throw std::out_of_range("principal minor index is out of range");
  }
  DenseMatrix<u64> result(value.rows() - 1, value.columns() - 1);
  for (size_t row = 0, target_row = 0; row < value.rows(); ++row) {
    if (row == removed) continue;
    for (size_t column = 0, target_column = 0; column < value.columns();
         ++column) {
      if (column == removed) continue;
      result[target_row][target_column++] = value[row][column];
    }
    ++target_row;
  }
  return result;
}

}  // namespace detail

// 无向图 Laplacian：L=D-A。自环忽略，平行边逐条累加。
inline DenseMatrix<u64> make_undirected_laplacian(
    size_t vertex_count, const vector<UndirectedEdge>& edges, u64 modulus) {
  detail::require_modulus(modulus);
  detail::require_nonempty_graph(vertex_count);
  DenseMatrix<u64> laplacian(vertex_count, vertex_count);
  for (const UndirectedEdge& edge : edges) {
    detail::require_vertex(edge.u, vertex_count);
    detail::require_vertex(edge.v, vertex_count);
    if (edge.u == edge.v) continue;
    const u64 weight = edge.weight % modulus;
    detail::add_to_cell(laplacian[edge.u][edge.u], weight, modulus);
    detail::add_to_cell(laplacian[edge.v][edge.v], weight, modulus);
    detail::subtract_from_cell(laplacian[edge.u][edge.v], weight, modulus);
    detail::subtract_from_cell(laplacian[edge.v][edge.u], weight, modulus);
  }
  return laplacian;
}

// TowardRoot 使用出度 Laplacian D_out-A；AwayFromRoot 使用入度版本，
// 即对边 from->to 更新 L[to][to] 和 L[to][from]。
inline DenseMatrix<u64> make_directed_laplacian(
    size_t vertex_count, const vector<DirectedEdge>& edges,
    ArborescenceDirection direction, u64 modulus) {
  detail::require_modulus(modulus);
  detail::require_nonempty_graph(vertex_count);
  detail::require_direction(direction);
  DenseMatrix<u64> laplacian(vertex_count, vertex_count);
  for (const DirectedEdge& edge : edges) {
    detail::require_vertex(edge.from, vertex_count);
    detail::require_vertex(edge.to, vertex_count);
    if (edge.from == edge.to) continue;
    const u64 weight = edge.weight % modulus;
    if (direction == ArborescenceDirection::TowardRoot) {
      detail::add_to_cell(laplacian[edge.from][edge.from], weight, modulus);
      detail::subtract_from_cell(laplacian[edge.from][edge.to], weight,
                                 modulus);
    } else {
      detail::add_to_cell(laplacian[edge.to][edge.to], weight, modulus);
      detail::subtract_from_cell(laplacian[edge.to][edge.from], weight,
                                 modulus);
    }
  }
  return laplacian;
}

// 结果是所有生成树边权乘积之和；单位权时就是生成树数量。
// prime_modulus 必须为质数。复杂度 O(n^3 + m)，空间 O(n^2)。
inline u64 count_spanning_trees_undirected(size_t vertex_count,
                                           const vector<UndirectedEdge>& edges,
                                           u64 prime_modulus) {
  detail::require_prime_modulus(prime_modulus);
  detail::require_nonempty_graph(vertex_count);
  DenseMatrix<u64> laplacian =
      make_undirected_laplacian(vertex_count, edges, prime_modulus);
  DenseMatrix<u64> minor = detail::principal_minor(laplacian, vertex_count - 1);
  return determinant_mod_prime(std::move(minor), prime_modulus);
}

inline u64 count_rooted_arborescences(size_t vertex_count,
                                      const vector<DirectedEdge>& edges,
                                      size_t root,
                                      ArborescenceDirection direction,
                                      u64 prime_modulus) {
  detail::require_prime_modulus(prime_modulus);
  detail::require_nonempty_graph(vertex_count);
  detail::require_vertex(root, vertex_count);
  detail::require_direction(direction);
  DenseMatrix<u64> laplacian =
      make_directed_laplacian(vertex_count, edges, direction, prime_modulus);
  DenseMatrix<u64> minor = detail::principal_minor(laplacian, root);
  return determinant_mod_prime(std::move(minor), prime_modulus);
}

inline u64 count_in_arborescences(size_t vertex_count,
                                  const vector<DirectedEdge>& edges,
                                  size_t root, u64 prime_modulus) {
  return count_rooted_arborescences(vertex_count, edges, root,
                                    ArborescenceDirection::TowardRoot,
                                    prime_modulus);
}

inline u64 count_out_arborescences(size_t vertex_count,
                                   const vector<DirectedEdge>& edges,
                                   size_t root, u64 prime_modulus) {
  return count_rooted_arborescences(vertex_count, edges, root,
                                    ArborescenceDirection::AwayFromRoot,
                                    prime_modulus);
}

enum class TropicalKind { MinPlus, MaxPlus };

// 当前半环的哨兵表示不可达，不能同时作为一个有限权值使用。
constexpr i64 MIN_PLUS_INF = std::numeric_limits<i64>::max();
constexpr i64 MAX_PLUS_NEG_INF = std::numeric_limits<i64>::lowest();

namespace detail {

inline void require_tropical_kind(TropicalKind kind) {
  if (kind != TropicalKind::MinPlus && kind != TropicalKind::MaxPlus) {
    throw std::invalid_argument("unknown tropical matrix kind");
  }
}

constexpr i64 tropical_unreachable(TropicalKind kind) noexcept {
  return kind == TropicalKind::MinPlus ? MIN_PLUS_INF : MAX_PLUS_NEG_INF;
}

template <TropicalKind Kind>
concept ValidTropicalKind =
    Kind == TropicalKind::MinPlus || Kind == TropicalKind::MaxPlus;

template <TropicalKind Kind>
  requires ValidTropicalKind<Kind>
constexpr i64 tropical_unreachable() noexcept {
  if constexpr (Kind == TropicalKind::MinPlus) {
    return MIN_PLUS_INF;
  } else {
    return MAX_PLUS_NEG_INF;
  }
}

template <TropicalKind Kind>
  requires ValidTropicalKind<Kind>
inline i64 checked_tropical_sum(i64 left, i64 right) {
  const i128 sum = static_cast<i128>(left) + static_cast<i128>(right);
  const i128 lowest = static_cast<i128>(std::numeric_limits<i64>::lowest());
  const i128 highest = static_cast<i128>(std::numeric_limits<i64>::max());
  if (sum < lowest || sum > highest ||
      (Kind == TropicalKind::MinPlus && sum == highest) ||
      (Kind == TropicalKind::MaxPlus && sum == lowest)) {
    throw std::overflow_error(
        "tropical path weight overflows or collides with infinity");
  }
  return static_cast<i64>(sum);
}

}  // namespace detail

template <TropicalKind Kind>
  requires detail::ValidTropicalKind<Kind>
[[nodiscard]] DenseMatrix<i64> tropical_identity(size_t size) {
  DenseMatrix<i64> result(size, size, detail::tropical_unreachable<Kind>());
  for (size_t i = 0; i < size; ++i) result[i][i] = 0;
  return result;
}

[[nodiscard]] inline DenseMatrix<i64> tropical_identity(size_t size,
                                                        TropicalKind kind) {
  detail::require_tropical_kind(kind);
  switch (kind) {
    case TropicalKind::MinPlus:
      return tropical_identity<TropicalKind::MinPlus>(size);
    case TropicalKind::MaxPlus:
      return tropical_identity<TropicalKind::MaxPlus>(size);
  }
  std::unreachable();
}

// Min-Plus: result[i][j] = min_k(left[i][k] + right[k][j])；
// Max-Plus 将 min 换成 max。有限和用 i128 检查，不做静默饱和。
template <TropicalKind Kind>
  requires detail::ValidTropicalKind<Kind>
[[nodiscard]] DenseMatrix<i64> tropical_multiply(
    const DenseMatrix<i64>& left, const DenseMatrix<i64>& right) {
  detail::require_multipliable(left, right);
  constexpr i64 unreachable = detail::tropical_unreachable<Kind>();
  DenseMatrix<i64> result(left.rows(), right.columns(), unreachable);
  for (size_t row = 0; row < left.rows(); ++row) {
    auto output = result[row];
    const auto left_row = left[row];
    for (size_t middle = 0; middle < left.columns(); ++middle) {
      if (left_row[middle] == unreachable) continue;
      const auto right_row = right[middle];
      for (size_t column = 0; column < right.columns(); ++column) {
        if (right_row[column] == unreachable) continue;
        const i64 candidate = detail::checked_tropical_sum<Kind>(
            left_row[middle], right_row[column]);
        i64& answer = output[column];
        if (answer == unreachable ||
            (Kind == TropicalKind::MinPlus && candidate < answer) ||
            (Kind == TropicalKind::MaxPlus && candidate > answer)) {
          answer = candidate;
        }
      }
    }
  }
  return result;
}

[[nodiscard]] inline DenseMatrix<i64> tropical_multiply(
    const DenseMatrix<i64>& left, const DenseMatrix<i64>& right,
    TropicalKind kind) {
  detail::require_tropical_kind(kind);
  switch (kind) {
    case TropicalKind::MinPlus:
      return tropical_multiply<TropicalKind::MinPlus>(left, right);
    case TropicalKind::MaxPlus:
      return tropical_multiply<TropicalKind::MaxPlus>(left, right);
  }
  std::unreachable();
}

// 邻接矩阵的 k 次幂表示恰好走 k 条边；要求至多 k 条边时，先将对角线
// 与 0 取 min/max，加入“原地不走”的转移。
template <TropicalKind Kind, detail::MatrixExponent Exponent>
  requires detail::ValidTropicalKind<Kind>
[[nodiscard]] DenseMatrix<i64> tropical_power(DenseMatrix<i64> base,
                                              Exponent exponent) {
  detail::require_square(base);
  u64 remaining = detail::checked_exponent(exponent);
  DenseMatrix<i64> result = tropical_identity<Kind>(base.rows());
  while (remaining > 0) {
    if (remaining & 1) result = tropical_multiply<Kind>(result, base);
    remaining >>= 1;
    if (remaining > 0) base = tropical_multiply<Kind>(base, base);
  }
  return result;
}

template <detail::MatrixExponent Exponent>
[[nodiscard]] DenseMatrix<i64> tropical_power(DenseMatrix<i64> base,
                                              Exponent exponent,
                                              TropicalKind kind) {
  detail::require_tropical_kind(kind);
  switch (kind) {
    case TropicalKind::MinPlus:
      return tropical_power<TropicalKind::MinPlus>(std::move(base), exponent);
    case TropicalKind::MaxPlus:
      return tropical_power<TropicalKind::MaxPlus>(std::move(base), exponent);
  }
  std::unreachable();
}

[[nodiscard]] inline DenseMatrix<i64> min_plus_multiply(
    const DenseMatrix<i64>& left, const DenseMatrix<i64>& right) {
  return tropical_multiply<TropicalKind::MinPlus>(left, right);
}

[[nodiscard]] inline DenseMatrix<i64> max_plus_multiply(
    const DenseMatrix<i64>& left, const DenseMatrix<i64>& right) {
  return tropical_multiply<TropicalKind::MaxPlus>(left, right);
}

template <detail::MatrixExponent Exponent>
[[nodiscard]] DenseMatrix<i64> min_plus_power(DenseMatrix<i64> base,
                                              Exponent exponent) {
  return tropical_power<TropicalKind::MinPlus>(std::move(base), exponent);
}

template <detail::MatrixExponent Exponent>
[[nodiscard]] DenseMatrix<i64> max_plus_power(DenseMatrix<i64> base,
                                              Exponent exponent) {
  return tropical_power<TropicalKind::MaxPlus>(std::move(base), exponent);
}

}  // namespace matrix

// 矩阵使用示例：
// matrix::DenseMatrix<u64> fib{{1, 1}, {1, 0}};
// auto fib_power = matrix::power_mod(fib, n, 1'000'000'007ULL);
// auto real_system = matrix::gaussian_elimination_real(
//     {{1, 2, 5}, {3, 4, 11}}, 2);  // 最后一列是常数
// auto mod_system = matrix::gaussian_elimination_prime_mod(
//     vector<vector<i64>>{{1, 2, 5}, {3, 4, 11}}, 2, 998244353);
// auto real_rank = matrix::rank_real(
//     matrix::DenseMatrix<f80>{{1, 2, 3}, {2, 4, 6}});
// auto mod_rank = matrix::rank_mod_prime(
//     matrix::DenseMatrix<i64>{{1, 2, 3}, {2, 4, 6}}, 998244353);
// vector<matrix::UndirectedEdge> graph_edges{{0, 1}, {1, 2}, {2, 0}};
// auto tree_count =
//     matrix::count_spanning_trees_undirected(3, graph_edges, 1'000'000'007);
// matrix::DenseMatrix<i64> distances(
//     n, n, matrix::MIN_PLUS_INF);  // distances[u][v] = 边权
// auto exactly_k_edges = matrix::min_plus_power(distances, k);

// 二维/三维计算几何。浮点构造统一使用 long double；需要分别控制距离、角度
// 与舍入误差时使用 Tolerance，旧接口的单个 EPS 保持为距离容差。
namespace geometry {

constexpr f80 DEFAULT_EPS = 1e-12L;
constexpr f80 DEFAULT_RELATIVE_EPS = 64 * std::numeric_limits<f80>::epsilon();

// distance 是坐标空间中的绝对距离容差；angle 是弧度/方向容差；
// relative 只用于吸收浮点运算自身的舍入误差。三者分开可避免把“长度 EPS”
// 直接拿去比较面积或角度。传入旧接口的单个 epsilon 只覆盖 distance。
struct Tolerance {
  f80 distance = DEFAULT_EPS;
  f80 angle = DEFAULT_RELATIVE_EPS;
  f80 relative = DEFAULT_RELATIVE_EPS;

  constexpr Tolerance() = default;
  explicit constexpr Tolerance(f80 distance_epsilon)
      : distance(distance_epsilon) {}
  constexpr Tolerance(f80 distance_epsilon, f80 angle_epsilon,
                      f80 relative_epsilon = DEFAULT_RELATIVE_EPS)
      : distance(distance_epsilon),
        angle(angle_epsilon),
        relative(relative_epsilon) {}

  [[nodiscard]] constexpr bool valid() const noexcept {
    return std::isfinite(distance) && std::isfinite(angle) &&
           std::isfinite(relative) && distance >= 0 && angle >= 0 &&
           relative >= 0;
  }
};

using ExactInteger = boost::multiprecision::int256_t;
using ArbitraryInteger = boost::multiprecision::cpp_int;

template <typename T>
inline constexpr bool is_bounded_integer_coordinate_v =
    (std::is_integral_v<std::remove_cv_t<T>> &&
     !std::is_same_v<std::remove_cv_t<T>, bool> && sizeof(T) <= sizeof(u64)) ||
    std::is_same_v<std::remove_cv_t<T>, ExactInteger>;

template <typename T>
inline constexpr bool is_exact_integer_coordinate_v =
    is_bounded_integer_coordinate_v<T> ||
    std::is_same_v<std::remove_cv_t<T>, ArbitraryInteger>;

// GCC 在严格 -std=c++23 下不把 __int128 计入 std::integral；几何坐标明确
// 限制为标准 64 位以内整数、浮点数或上面的 Boost 整数，避免误走浮点谓词。
template <typename T>
concept Coordinate = is_exact_integer_coordinate_v<T> ||
                     std::floating_point<std::remove_cv_t<T>>;

template <typename T>
using Calculation = std::conditional_t<
    std::is_same_v<std::remove_cv_t<T>, ExactInteger> ||
        std::is_same_v<std::remove_cv_t<T>, ArbitraryInteger>,
    ArbitraryInteger,
    std::conditional_t<is_exact_integer_coordinate_v<T>, ExactInteger,
                       long double>>;

template <Coordinate T>
struct Point2 {
  T x{};
  T y{};

  constexpr Point2() = default;
  constexpr Point2(T x_value, T y_value) : x(x_value), y(y_value) {}

  Point2 operator+() const noexcept { return *this; }
  Point2 operator-() const {
    if constexpr (is_bounded_integer_coordinate_v<T>) {
      return {checked_coordinate(-static_cast<Calculation<T>>(x)),
              checked_coordinate(-static_cast<Calculation<T>>(y))};
    } else {
      return {-x, -y};
    }
  }

  Point2& operator+=(const Point2& other) {
    if constexpr (is_bounded_integer_coordinate_v<T>) {
      const T next_x =
          checked_coordinate(static_cast<Calculation<T>>(x) + other.x);
      const T next_y =
          checked_coordinate(static_cast<Calculation<T>>(y) + other.y);
      x = next_x;
      y = next_y;
    } else {
      x += other.x;
      y += other.y;
    }
    return *this;
  }

  Point2& operator-=(const Point2& other) {
    if constexpr (is_bounded_integer_coordinate_v<T>) {
      const T next_x =
          checked_coordinate(static_cast<Calculation<T>>(x) - other.x);
      const T next_y =
          checked_coordinate(static_cast<Calculation<T>>(y) - other.y);
      x = next_x;
      y = next_y;
    } else {
      x -= other.x;
      y -= other.y;
    }
    return *this;
  }

  Point2& operator*=(T scalar) {
    if constexpr (is_bounded_integer_coordinate_v<T>) {
      const T next_x =
          checked_coordinate(static_cast<Calculation<T>>(x) * scalar);
      const T next_y =
          checked_coordinate(static_cast<Calculation<T>>(y) * scalar);
      x = next_x;
      y = next_y;
    } else {
      x *= scalar;
      y *= scalar;
    }
    return *this;
  }

  Point2& operator/=(T scalar) {
    if (scalar == T{}) {
      throw std::invalid_argument("Point2 division by zero");
    }
    if constexpr (is_bounded_integer_coordinate_v<T>) {
      const T next_x =
          checked_coordinate(static_cast<Calculation<T>>(x) / scalar);
      const T next_y =
          checked_coordinate(static_cast<Calculation<T>>(y) / scalar);
      x = next_x;
      y = next_y;
    } else {
      x /= scalar;
      y /= scalar;
    }
    return *this;
  }

  friend Point2 operator+(Point2 left, const Point2& right) {
    return left += right;
  }

  friend Point2 operator-(Point2 left, const Point2& right) {
    return left -= right;
  }

  friend Point2 operator*(Point2 point, T scalar) { return point *= scalar; }

  friend Point2 operator*(T scalar, Point2 point) { return point *= scalar; }

  friend Point2 operator/(Point2 point, T scalar) { return point /= scalar; }

  friend constexpr bool operator==(const Point2& left,
                                   const Point2& right) noexcept {
    return left.x == right.x && left.y == right.y;
  }

  friend constexpr bool operator!=(const Point2& left,
                                   const Point2& right) noexcept {
    return !(left == right);
  }

  // 精确字典序保证 sort 的严格弱序；浮点近似相等请用 almost_equal。
  friend constexpr bool operator<(const Point2& left,
                                  const Point2& right) noexcept {
    return left.x < right.x || (!(right.x < left.x) && left.y < right.y);
  }

 private:
  static T checked_coordinate(const Calculation<T>& value) {
    const Calculation<T> lowest =
        static_cast<Calculation<T>>(std::numeric_limits<T>::lowest());
    const Calculation<T> highest =
        static_cast<Calculation<T>>(std::numeric_limits<T>::max());
    if (value < lowest || value > highest) {
      throw std::overflow_error("Point2 coordinate arithmetic overflow");
    }
    return static_cast<T>(value);
  }
};

using Point = Point2<f80>;
using IPoint = Point2<i64>;

namespace detail {

struct ScaledVector2 {
  f80 x{};
  f80 y{};
  f80 scale{};
  f80 normalized_length{};
};

[[nodiscard]] inline ScaledVector2 scale_vector(const Point& value) noexcept {
  const f80 scale = std::max(std::abs(value.x), std::abs(value.y));
  if (scale == 0 || !std::isfinite(scale)) return {{}, {}, scale, {}};
  const f80 x = value.x / scale;
  const f80 y = value.y / scale;
  return {x, y, scale, std::hypotl(x, y)};
}

[[nodiscard]] inline bool vector_is_zero(const Point& value,
                                         f80 epsilon) noexcept {
  if (!std::isfinite(value.x) || !std::isfinite(value.y) ||
      !std::isfinite(epsilon) || epsilon < 0) {
    return true;
  }
  const ScaledVector2 scaled = scale_vector(value);
  if (scaled.scale == 0) return true;
  // 比较 scale * normalized_length <= epsilon，但不形成可能溢出的乘积。
  return scaled.scale <= epsilon / scaled.normalized_length;
}

[[nodiscard]] inline Point normalized_vector(const Point& value, f80 epsilon) {
  if (!std::isfinite(value.x) || !std::isfinite(value.y) ||
      !std::isfinite(epsilon) || epsilon < 0) {
    throw std::invalid_argument("cannot normalize a non-finite vector");
  }
  const ScaledVector2 scaled = scale_vector(value);
  if (scaled.scale == 0 || scaled.scale <= epsilon / scaled.normalized_length) {
    throw std::invalid_argument("cannot normalize a zero vector");
  }
  return {scaled.x / scaled.normalized_length,
          scaled.y / scaled.normalized_length};
}

[[nodiscard]] inline f80 normalized_cross(
    const ScaledVector2& first, const ScaledVector2& second) noexcept {
  return std::fma(first.x, second.y, -first.y * second.x);
}

[[nodiscard]] inline f80 cross_roundoff_bound(const ScaledVector2& first,
                                              const ScaledVector2& second,
                                              f80 relative_epsilon) noexcept {
  return relative_epsilon *
         (std::abs(first.x * second.y) + std::abs(first.y * second.x));
}

[[nodiscard]] inline bool directions_parallel(
    const Point& first, const Point& second,
    const Tolerance& tolerance) noexcept {
  const ScaledVector2 a = scale_vector(first);
  const ScaledVector2 b = scale_vector(second);
  if (a.scale == 0 || b.scale == 0 || !std::isfinite(a.scale) ||
      !std::isfinite(b.scale)) {
    return true;
  }
  const f80 determinant = std::abs(normalized_cross(a, b));
  const f80 threshold =
      tolerance.angle * a.normalized_length * b.normalized_length +
      cross_roundoff_bound(a, b, tolerance.relative);
  return determinant <= threshold;
}

[[nodiscard]] inline int floating_orientation(
    const Point& first, const Point& second, const Point& third,
    const Tolerance& tolerance) noexcept {
  const Point edge{second.x - first.x, second.y - first.y};
  const Point offset{third.x - first.x, third.y - first.y};
  const ScaledVector2 a = scale_vector(edge);
  const ScaledVector2 b = scale_vector(offset);
  if (a.scale == 0 || b.scale == 0) return 0;
  if (!std::isfinite(a.scale) || !std::isfinite(b.scale)) {
    const f80 determinant =
        std::fma(second.x - first.x, third.y - first.y,
                 -(second.y - first.y) * (third.x - first.x));
    return (determinant > 0) - (determinant < 0);
  }

  const f80 determinant = normalized_cross(a, b);
  const f80 absolute_determinant = std::abs(determinant);
  if (absolute_determinant <= cross_roundoff_bound(a, b, tolerance.relative)) {
    return 0;
  }
  // |cross(edge, offset)| / |edge| 是点到直线的垂直距离。缩放后比较，
  // 避免 epsilon（长度）与叉积（长度平方）直接比较。
  if (tolerance.distance > 0 &&
      absolute_determinant <=
          (tolerance.distance / b.scale) * a.normalized_length) {
    return 0;
  }
  return determinant > 0 ? 1 : -1;
}

}  // namespace detail

// 整数谓词提升到 256 位，覆盖完整 i64 二维叉积、点积与距离平方。
template <typename T>
Calculation<T> dot(const Point2<T>& left, const Point2<T>& right) {
  using C = Calculation<T>;
  return static_cast<C>(left.x) * static_cast<C>(right.x) +
         static_cast<C>(left.y) * static_cast<C>(right.y);
}

template <typename T>
Calculation<T> cross(const Point2<T>& left, const Point2<T>& right) {
  using C = Calculation<T>;
  return static_cast<C>(left.x) * static_cast<C>(right.y) -
         static_cast<C>(left.y) * static_cast<C>(right.x);
}

template <typename T>
Calculation<T> cross(const Point2<T>& origin, const Point2<T>& first,
                     const Point2<T>& second) {
  using C = Calculation<T>;
  const C ax = static_cast<C>(first.x) - static_cast<C>(origin.x);
  const C ay = static_cast<C>(first.y) - static_cast<C>(origin.y);
  const C bx = static_cast<C>(second.x) - static_cast<C>(origin.x);
  const C by = static_cast<C>(second.y) - static_cast<C>(origin.y);
  return ax * by - ay * bx;
}

template <typename T>
Calculation<T> norm_squared(const Point2<T>& value) {
  return dot(value, value);
}

template <typename T>
f80 length(const Point2<T>& value) noexcept {
  return std::hypotl(static_cast<f80>(value.x), static_cast<f80>(value.y));
}

template <typename T>
f80 distance(const Point2<T>& first, const Point2<T>& second) noexcept {
  return std::hypotl(static_cast<f80>(first.x) - static_cast<f80>(second.x),
                     static_cast<f80>(first.y) - static_cast<f80>(second.y));
}

inline bool almost_equal(f80 left, f80 right,
                         f80 epsilon = DEFAULT_EPS) noexcept {
  return std::abs(left - right) <= epsilon;
}

inline bool almost_equal(const Point& left, const Point& right,
                         f80 epsilon = DEFAULT_EPS) noexcept {
  return distance(left, right) <= epsilon;
}

template <typename T>
int sign(Calculation<T> value, f80 epsilon = DEFAULT_EPS) noexcept {
  if constexpr (is_exact_integer_coordinate_v<T>) {
    return (value > 0) - (value < 0);
  } else {
    return value > epsilon ? 1 : (value < -epsilon ? -1 : 0);
  }
}

template <typename T>
int orientation(const Point2<T>& first, const Point2<T>& second,
                const Point2<T>& third, const Tolerance& tolerance) noexcept {
  if constexpr (is_exact_integer_coordinate_v<T>) {
    return sign<T>(cross(first, second, third), 0);
  } else {
    return detail::floating_orientation(
        {static_cast<f80>(first.x), static_cast<f80>(first.y)},
        {static_cast<f80>(second.x), static_cast<f80>(second.y)},
        {static_cast<f80>(third.x), static_cast<f80>(third.y)}, tolerance);
  }
}

template <typename T>
int orientation(const Point2<T>& first, const Point2<T>& second,
                const Point2<T>& third, f80 epsilon = DEFAULT_EPS) noexcept {
  return orientation(first, second, third, Tolerance(epsilon));
}

inline Point unit(const Point& value, f80 epsilon = DEFAULT_EPS) {
  return detail::normalized_vector(value, epsilon);
}

inline Point perpendicular_left(const Point& value) noexcept {
  return {-value.y, value.x};
}

inline Point rotate(const Point& value, f80 angle) noexcept {
  const f80 cosine = std::cos(angle);
  const f80 sine = std::sin(angle);
  return {value.x * cosine - value.y * sine, value.x * sine + value.y * cosine};
}

inline f80 angle_between(const Point& first, const Point& second,
                         f80 epsilon = DEFAULT_EPS) {
  const Point first_unit = unit(first, epsilon);
  const Point second_unit = unit(second, epsilon);
  const f80 cosine = std::clamp(static_cast<f80>(dot(first_unit, second_unit)),
                                static_cast<f80>(-1), static_cast<f80>(1));
  return std::acos(cosine);
}

// 不在比较器中使用 EPS，否则可能破坏严格弱序。零向量排在最前。
template <typename T>
class PolarAngleLess {
 public:
  explicit constexpr PolarAngleLess(Point2<T> origin = {}) noexcept
      : origin_(origin) {}

  // 浮点输入要求坐标有限；polar_sort 会主动检查。
  bool operator()(const Point2<T>& left, const Point2<T>& right) const {
    using C = Calculation<T>;
    const C lx = static_cast<C>(left.x) - static_cast<C>(origin_.x);
    const C ly = static_cast<C>(left.y) - static_cast<C>(origin_.y);
    const C rx = static_cast<C>(right.x) - static_cast<C>(origin_.x);
    const C ry = static_cast<C>(right.y) - static_cast<C>(origin_.y);
    if constexpr (is_exact_integer_coordinate_v<T>) {
      const int left_half = half(lx, ly);
      const int right_half = half(rx, ry);
      if (left_half != right_half) return left_half < right_half;
      const C product = lx * ry - ly * rx;
      if (product != 0) return product > 0;
      const C left_distance = lx * lx + ly * ly;
      const C right_distance = rx * rx + ry * ry;
      if (left_distance != right_distance) {
        return left_distance < right_distance;
      }
    } else {
      const int left_half = half(lx, ly);
      const int right_half = half(rx, ry);
      if (left_half != right_half) return left_half < right_half;

      const Point left_vector{static_cast<f80>(lx), static_cast<f80>(ly)};
      const Point right_vector{static_cast<f80>(rx), static_cast<f80>(ry)};
      const detail::ScaledVector2 left_scaled =
          detail::scale_vector(left_vector);
      const detail::ScaledVector2 right_scaled =
          detail::scale_vector(right_vector);
      const f80 product = detail::normalized_cross(left_scaled, right_scaled);
      if (product != 0) return product > 0;

      // 用同一个正比例缩放两向量后比较平方长度，避免 LDBL_MAX 级坐标
      // 的平方溢出；比较器不使用 EPS，仍保持严格弱序。
      const f80 common_scale = std::max(left_scaled.scale, right_scaled.scale);
      if (common_scale > 0) {
        const f80 left_x = static_cast<f80>(lx) / common_scale;
        const f80 left_y = static_cast<f80>(ly) / common_scale;
        const f80 right_x = static_cast<f80>(rx) / common_scale;
        const f80 right_y = static_cast<f80>(ry) / common_scale;
        const f80 left_distance = std::fma(left_x, left_x, left_y * left_y);
        const f80 right_distance =
            std::fma(right_x, right_x, right_y * right_y);
        if (left_distance != right_distance) {
          return left_distance < right_distance;
        }
      }
    }
    return left < right;
  }

 private:
  static int half(const Calculation<T>& x, const Calculation<T>& y) noexcept {
    return y > 0 || (y == 0 && x >= 0) ? 0 : 1;
  }

  Point2<T> origin_;
};

template <typename T>
void polar_sort(vector<Point2<T>>& points, Point2<T> origin = {}) {
  if constexpr (!is_exact_integer_coordinate_v<T>) {
    if (!std::isfinite(origin.x) || !std::isfinite(origin.y)) {
      throw std::invalid_argument("polar_sort requires finite points");
    }
    for (const Point2<T>& point : points) {
      if (!std::isfinite(point.x) || !std::isfinite(point.y)) {
        throw std::invalid_argument("polar_sort requires finite points");
      }
    }
  }
  std::ranges::sort(points, PolarAngleLess<T>(origin));
}

template <typename T>
struct Segment2 {
  Point2<T> first;
  Point2<T> second;
};

template <typename T>
bool on_segment(const Point2<T>& point, const Segment2<T>& segment,
                f80 epsilon = DEFAULT_EPS) noexcept {
  if (orientation(segment.first, segment.second, point, epsilon) != 0) {
    return false;
  }
  if constexpr (is_exact_integer_coordinate_v<T>) {
    using C = Calculation<T>;
    const C ax = static_cast<C>(point.x) - static_cast<C>(segment.first.x);
    const C ay = static_cast<C>(point.y) - static_cast<C>(segment.first.y);
    const C bx = static_cast<C>(point.x) - static_cast<C>(segment.second.x);
    const C by = static_cast<C>(point.y) - static_cast<C>(segment.second.y);
    const C product = ax * bx + ay * by;
    return product <= 0;
  } else {
    return point.x >= std::min(segment.first.x, segment.second.x) - epsilon &&
           point.x <= std::max(segment.first.x, segment.second.x) + epsilon &&
           point.y >= std::min(segment.first.y, segment.second.y) - epsilon &&
           point.y <= std::max(segment.first.y, segment.second.y) + epsilon;
  }
}

enum class SegmentIntersectionType { None, SinglePoint, Overlap };

namespace detail {

template <typename T>
bool same_point(const Point2<T>& left, const Point2<T>& right,
                f80 epsilon) noexcept {
  if constexpr (is_exact_integer_coordinate_v<T>) {
    return left == right;
  } else {
    return distance(left, right) <= epsilon;
  }
}

template <typename T>
vector<Point2<T>> common_segment_endpoints(const Segment2<T>& first,
                                           const Segment2<T>& second,
                                           f80 epsilon) {
  const std::array<Point2<T>, 4> candidates{first.first, first.second,
                                            second.first, second.second};
  vector<Point2<T>> result;
  for (const Point2<T>& point : candidates) {
    if (!on_segment(point, first, epsilon) ||
        !on_segment(point, second, epsilon)) {
      continue;
    }
    bool duplicate = false;
    for (const Point2<T>& existing : result) {
      if (same_point(point, existing, epsilon)) {
        duplicate = true;
        break;
      }
    }
    if (!duplicate) result.push_back(point);
  }
  std::sort(result.begin(), result.end());
  return result;
}

}  // namespace detail

template <typename T>
SegmentIntersectionType segment_intersection_type(const Segment2<T>& first,
                                                  const Segment2<T>& second,
                                                  f80 epsilon = DEFAULT_EPS) {
  const int o1 = orientation(first.first, first.second, second.first, epsilon);
  const int o2 = orientation(first.first, first.second, second.second, epsilon);
  const int o3 = orientation(second.first, second.second, first.first, epsilon);
  const int o4 =
      orientation(second.first, second.second, first.second, epsilon);
  if (o1 == 0 && o2 == 0 && o3 == 0 && o4 == 0) {
    const auto common =
        detail::common_segment_endpoints(first, second, epsilon);
    if (common.empty()) return SegmentIntersectionType::None;
    return common.size() == 1 ? SegmentIntersectionType::SinglePoint
                              : SegmentIntersectionType::Overlap;
  }
  return o1 * o2 <= 0 && o3 * o4 <= 0 ? SegmentIntersectionType::SinglePoint
                                      : SegmentIntersectionType::None;
}

template <typename T>
bool segments_intersect(const Segment2<T>& first, const Segment2<T>& second,
                        f80 epsilon = DEFAULT_EPS) {
  return segment_intersection_type(first, second, epsilon) !=
         SegmentIntersectionType::None;
}

template <typename T>
bool segments_properly_intersect(const Segment2<T>& first,
                                 const Segment2<T>& second,
                                 f80 epsilon = DEFAULT_EPS) noexcept {
  const int o1 = orientation(first.first, first.second, second.first, epsilon);
  const int o2 = orientation(first.first, first.second, second.second, epsilon);
  const int o3 = orientation(second.first, second.second, first.first, epsilon);
  const int o4 =
      orientation(second.first, second.second, first.second, epsilon);
  return o1 * o2 < 0 && o3 * o4 < 0;
}

struct Line2 {
  Point point;
  Point direction;
};

inline Line2 line_through(const Point& first, const Point& second,
                          f80 epsilon = DEFAULT_EPS) {
  const Point direction = second - first;
  if (detail::vector_is_zero(direction, epsilon)) {
    throw std::invalid_argument("a line requires two distinct points");
  }
  return {first, direction};
}

enum class LineIntersectionType { None, SinglePoint, Coincident };

struct LineIntersectionResult {
  LineIntersectionType type = LineIntersectionType::None;
  Point point{};
};

inline LineIntersectionResult intersect_lines(const Line2& first,
                                              const Line2& second,
                                              const Tolerance& tolerance) {
  if (!tolerance.valid()) {
    throw std::invalid_argument("invalid geometry tolerance");
  }
  if (detail::vector_is_zero(first.direction, tolerance.distance) ||
      detail::vector_is_zero(second.direction, tolerance.distance)) {
    throw std::invalid_argument("line direction must be non-zero");
  }
  const Point first_direction = unit(first.direction, tolerance.distance);
  const Point second_direction = unit(second.direction, tolerance.distance);
  const Point displacement = second.point - first.point;
  if (!std::isfinite(displacement.x) || !std::isfinite(displacement.y)) {
    throw std::overflow_error("line point difference overflow");
  }
  if (detail::directions_parallel(first_direction, second_direction,
                                  tolerance)) {
    const f80 offset = std::abs(cross(displacement, first_direction));
    return {offset <= tolerance.distance ? LineIntersectionType::Coincident
                                         : LineIntersectionType::None,
            {}};
  }
  const f80 denominator = cross(first_direction, second_direction);
  const f80 parameter = cross(displacement, second_direction) / denominator;
  const Point intersection = first.point + first_direction * parameter;
  if (!std::isfinite(intersection.x) || !std::isfinite(intersection.y)) {
    throw std::overflow_error("line intersection is not representable");
  }
  return {LineIntersectionType::SinglePoint, intersection};
}

inline LineIntersectionResult intersect_lines(const Line2& first,
                                              const Line2& second,
                                              f80 epsilon = DEFAULT_EPS) {
  return intersect_lines(first, second, Tolerance(epsilon));
}

struct SegmentIntersectionResult {
  SegmentIntersectionType type = SegmentIntersectionType::None;
  Point first{};
  Point second{};  // Overlap 时为另一个端点；Point 时等于 first。
};

inline SegmentIntersectionResult intersect_segments(const Segment2<f80>& first,
                                                    const Segment2<f80>& second,
                                                    f80 epsilon = DEFAULT_EPS) {
  const SegmentIntersectionType type =
      segment_intersection_type(first, second, epsilon);
  if (type == SegmentIntersectionType::None) return {};

  const auto common = detail::common_segment_endpoints(first, second, epsilon);
  if (type == SegmentIntersectionType::Overlap) {
    return {type, common.front(), common.back()};
  }
  if (!common.empty()) return {type, common.front(), common.front()};

  const auto intersection = intersect_lines(
      line_through(first.first, first.second, epsilon),
      line_through(second.first, second.second, epsilon), Tolerance(epsilon));
  if (intersection.type != LineIntersectionType::SinglePoint) {
    // 绝不在 Release 中把默认构造的 (0, 0) 冒充交点。到达这里说明输入的
    // 尺度已经低于当前浮点方向分辨率，分类结果也应保守地视为无交点。
    return {};
  }
  return {type, intersection.point, intersection.point};
}

inline Point project_onto_line(const Point& point, const Line2& line,
                               f80 epsilon = DEFAULT_EPS) {
  const Point direction = unit(line.direction, epsilon);
  const f80 parameter = dot(point - line.point, direction);
  return line.point + direction * parameter;
}

inline Point reflect_across_line(const Point& point, const Line2& line,
                                 f80 epsilon = DEFAULT_EPS) {
  const Point projection = project_onto_line(point, line, epsilon);
  return projection * 2 - point;
}

inline f80 distance_to_line(const Point& point, const Line2& line,
                            f80 epsilon = DEFAULT_EPS) {
  const Point direction = unit(line.direction, epsilon);
  return std::abs(cross(direction, point - line.point));
}

inline Point closest_point_on_segment(const Point& point,
                                      const Segment2<f80>& segment,
                                      f80 epsilon = DEFAULT_EPS) {
  const Point direction = segment.second - segment.first;
  const f80 denominator = static_cast<f80>(norm_squared(direction));
  if (denominator <= epsilon * epsilon) return segment.first;
  const f80 parameter = std::clamp(
      static_cast<f80>(dot(point - segment.first, direction)) / denominator,
      static_cast<f80>(0), static_cast<f80>(1));
  return segment.first + direction * parameter;
}

inline f80 distance_to_segment(const Point& point, const Segment2<f80>& segment,
                               f80 epsilon = DEFAULT_EPS) {
  return distance(point, closest_point_on_segment(point, segment, epsilon));
}

inline f80 distance_between_segments(const Segment2<f80>& first,
                                     const Segment2<f80>& second,
                                     f80 epsilon = DEFAULT_EPS) {
  if (segments_intersect(first, second, epsilon)) return 0;
  return std::min({distance_to_segment(first.first, second, epsilon),
                   distance_to_segment(first.second, second, epsilon),
                   distance_to_segment(second.first, first, epsilon),
                   distance_to_segment(second.second, first, epsilon)});
}

template <typename T>
Calculation<T> polygon_twice_signed_area(const vector<Point2<T>>& polygon) {
  Calculation<T> result = 0;
  for (size_t i = 0; i < polygon.size(); ++i) {
    result += cross(polygon[i], polygon[(i + 1) % polygon.size()]);
  }
  return result;
}

template <typename T>
f80 polygon_area(const vector<Point2<T>>& polygon) noexcept {
  return std::abs(static_cast<f80>(polygon_twice_signed_area(polygon))) / 2;
}

template <typename T>
f80 polygon_perimeter(const vector<Point2<T>>& polygon) noexcept {
  if (polygon.size() < 2) return 0;
  f80 result = 0;
  for (size_t i = 0; i < polygon.size(); ++i) {
    result += distance(polygon[i], polygon[(i + 1) % polygon.size()]);
  }
  return result;
}

inline optional<Point> polygon_centroid(const vector<Point>& polygon,
                                        f80 epsilon = DEFAULT_EPS) {
  f80 twice_area = 0;
  Point weighted{};
  for (size_t i = 0; i < polygon.size(); ++i) {
    const Point& current = polygon[i];
    const Point& next = polygon[(i + 1) % polygon.size()];
    const f80 weight = cross(current, next);
    twice_area += weight;
    weighted += (current + next) * weight;
  }
  if (std::abs(twice_area) <= epsilon) return nullopt;
  return weighted / (3 * twice_area);
}

enum class PointPolygonLocation { Outside, Boundary, Inside };

template <typename T>
PointPolygonLocation locate_point_in_polygon(const Point2<T>& point,
                                             const vector<Point2<T>>& polygon,
                                             f80 epsilon = DEFAULT_EPS) {
  if (polygon.empty()) return PointPolygonLocation::Outside;
  int winding = 0;
  for (size_t i = 0; i < polygon.size(); ++i) {
    const Point2<T>& first = polygon[i];
    const Point2<T>& second = polygon[(i + 1) % polygon.size()];
    if (on_segment(point, Segment2<T>{first, second}, epsilon)) {
      return PointPolygonLocation::Boundary;
    }
    if (first.y <= point.y && point.y < second.y &&
        orientation(first, second, point, epsilon) > 0) {
      ++winding;
    } else if (second.y <= point.y && point.y < first.y &&
               orientation(first, second, point, epsilon) < 0) {
      --winding;
    }
  }
  return winding == 0 ? PointPolygonLocation::Outside
                      : PointPolygonLocation::Inside;
}

struct Circle2 {
  Point center{};
  f80 radius = 0;

  Circle2() = default;
  Circle2(Point center_value, f80 radius_value)
      : center(center_value), radius(radius_value) {
    if (!std::isfinite(radius) || radius < 0) {
      throw std::invalid_argument(
          "circle radius must be finite and non-negative");
    }
  }
};

inline vector<Point> intersect_line_circle(const Line2& line,
                                           const Circle2& circle,
                                           f80 epsilon = DEFAULT_EPS) {
  const Point projection = project_onto_line(circle.center, line, epsilon);
  const f80 center_distance = distance(projection, circle.center);
  if (center_distance > circle.radius + epsilon) return {};
  if (std::abs(center_distance - circle.radius) <= epsilon) {
    return {projection};
  }
  const f80 offset = std::sqrt(std::max(
      static_cast<f80>(0),
      circle.radius * circle.radius - center_distance * center_distance));
  const Point direction = unit(line.direction, epsilon);
  return {projection - direction * offset, projection + direction * offset};
}

enum class CircleIntersectionType { None, Tangent, TwoPoints, Coincident };

struct CircleIntersectionResult {
  CircleIntersectionType type = CircleIntersectionType::None;
  vector<Point> points;
};

inline CircleIntersectionResult intersect_circles(const Circle2& first,
                                                  const Circle2& second,
                                                  f80 epsilon = DEFAULT_EPS) {
  const Point delta = second.center - first.center;
  const f80 center_distance = length(delta);
  if (center_distance <= epsilon &&
      std::abs(first.radius - second.radius) <= epsilon) {
    return {CircleIntersectionType::Coincident, {}};
  }
  if (center_distance > first.radius + second.radius + epsilon ||
      center_distance + std::min(first.radius, second.radius) + epsilon <
          std::max(first.radius, second.radius) ||
      center_distance <= epsilon) {
    return {};
  }

  const f80 along =
      (first.radius * first.radius - second.radius * second.radius +
       center_distance * center_distance) /
      (2 * center_distance);
  const f80 height_squared = first.radius * first.radius - along * along;
  const Point base = first.center + delta * (along / center_distance);
  if (height_squared <= epsilon * epsilon) {
    return {CircleIntersectionType::Tangent, {base}};
  }
  const f80 height = std::sqrt(std::max(static_cast<f80>(0), height_squared));
  const Point offset = perpendicular_left(delta) * (height / center_distance);
  return {CircleIntersectionType::TwoPoints, {base - offset, base + offset}};
}

inline optional<Circle2> circumcircle(const Point& first, const Point& second,
                                      const Point& third,
                                      f80 epsilon = DEFAULT_EPS) {
  if (orientation(first, second, third, epsilon) == 0) return nullopt;
  const Point a = second - first;
  const Point b = third - first;
  const f80 denominator = 2 * cross(a, b);
  const f80 a_squared = norm_squared(a);
  const f80 b_squared = norm_squared(b);
  const Point relative_center{
      (a_squared * b.y - b_squared * a.y) / denominator,
      (a.x * b_squared - b.x * a_squared) / denominator};
  const Point center = first + relative_center;
  if (!std::isfinite(center.x) || !std::isfinite(center.y)) return nullopt;
  return Circle2(center, distance(center, first));
}

template <typename T>
Calculation<T> distance_squared(const Point2<T>& first,
                                const Point2<T>& second) {
  using C = Calculation<T>;
  const C dx = static_cast<C>(first.x) - static_cast<C>(second.x);
  const C dy = static_cast<C>(first.y) - static_cast<C>(second.y);
  return dx * dx + dy * dy;
}

template <typename T>
Point2<T> checked_add_point(const Point2<T>& first, const Point2<T>& second) {
  if constexpr (is_bounded_integer_coordinate_v<T>) {
    using C = Calculation<T>;
    const C x = static_cast<C>(first.x) + static_cast<C>(second.x);
    const C y = static_cast<C>(first.y) + static_cast<C>(second.y);
    const C lowest = static_cast<C>(std::numeric_limits<T>::lowest());
    const C highest = static_cast<C>(std::numeric_limits<T>::max());
    if (x < lowest || x > highest || y < lowest || y > highest) {
      throw std::overflow_error("Point2 addition overflows coordinate");
    }
    return {static_cast<T>(x), static_cast<T>(y)};
  } else {
    return first + second;
  }
}

template <typename T>
Point2<T> checked_subtract_point(const Point2<T>& first,
                                 const Point2<T>& second) {
  if constexpr (is_bounded_integer_coordinate_v<T>) {
    using C = Calculation<T>;
    const C x = static_cast<C>(first.x) - static_cast<C>(second.x);
    const C y = static_cast<C>(first.y) - static_cast<C>(second.y);
    const C lowest = static_cast<C>(std::numeric_limits<T>::lowest());
    const C highest = static_cast<C>(std::numeric_limits<T>::max());
    if (x < lowest || x > highest || y < lowest || y > highest) {
      throw std::overflow_error("Point2 subtraction overflows coordinate");
    }
    return {static_cast<T>(x), static_cast<T>(y)};
  } else {
    return first - second;
  }
}

// Andrew 凸包：输出不重复首点，非退化时逆时针且从字典序最小点开始。
// keep_collinear=false 只保留极点；全共线时分别返回两端或全部有序点。
template <typename T>
vector<Point2<T>> convex_hull(vector<Point2<T>> points,
                              bool keep_collinear = false,
                              f80 epsilon = DEFAULT_EPS) {
  if constexpr (!is_exact_integer_coordinate_v<T>) {
    for (const Point2<T>& point : points) {
      if (!std::isfinite(point.x) || !std::isfinite(point.y)) {
        throw std::invalid_argument("convex_hull requires finite points");
      }
    }
  }
  std::sort(points.begin(), points.end());
  points.erase(std::unique(points.begin(), points.end()), points.end());
  if (points.size() <= 1) return points;

  bool all_collinear = true;
  for (size_t i = 1; i + 1 < points.size(); ++i) {
    if (orientation(points.front(), points.back(), points[i], epsilon) != 0) {
      all_collinear = false;
      break;
    }
  }
  if (all_collinear) {
    if (keep_collinear) return points;
    return {points.front(), points.back()};
  }

  auto should_remove = [keep_collinear, epsilon](const Point2<T>& first,
                                                 const Point2<T>& second,
                                                 const Point2<T>& third) {
    const int turn = orientation(first, second, third, epsilon);
    return keep_collinear ? turn < 0 : turn <= 0;
  };

  vector<Point2<T>> lower;
  for (const Point2<T>& point : points) {
    while (lower.size() >= 2 &&
           should_remove(lower[lower.size() - 2], lower.back(), point)) {
      lower.pop_back();
    }
    lower.push_back(point);
  }

  vector<Point2<T>> upper;
  for (auto iterator = points.rbegin(); iterator != points.rend(); ++iterator) {
    while (upper.size() >= 2 &&
           should_remove(upper[upper.size() - 2], upper.back(), *iterator)) {
      upper.pop_back();
    }
    upper.push_back(*iterator);
  }
  lower.pop_back();
  upper.pop_back();
  lower.insert(lower.end(), upper.begin(), upper.end());
  return lower;
}

template <typename T>
struct FarthestPairResult {
  Calculation<T> distance_squared{};
  Point2<T> first{};
  Point2<T> second{};
};

namespace detail {

template <typename T>
void update_farthest(FarthestPairResult<T>& result, const Point2<T>& first,
                     const Point2<T>& second) {
  const Calculation<T> candidate = distance_squared(first, second);
  if (candidate > result.distance_squared) {
    result = {candidate, first, second};
  }
}

}  // namespace detail

// 先取严格凸包，再用旋转卡壳求最远点对，O(n log n)。
template <typename T>
FarthestPairResult<T> farthest_pair(vector<Point2<T>> points,
                                    f80 epsilon = DEFAULT_EPS) {
  const vector<Point2<T>> hull = convex_hull(std::move(points), false, epsilon);
  FarthestPairResult<T> result;
  if (hull.empty()) return result;
  result.first = result.second = hull.front();
  if (hull.size() == 1) return result;
  if (hull.size() == 2) {
    detail::update_farthest(result, hull[0], hull[1]);
    return result;
  }

  size_t opposite = 1;
  for (size_t i = 0; i < hull.size(); ++i) {
    const size_t next_i = (i + 1) % hull.size();
    while (true) {
      const size_t next_opposite = (opposite + 1) % hull.size();
      const auto current_area = cross(hull[i], hull[next_i], hull[opposite]);
      const auto next_area = cross(hull[i], hull[next_i], hull[next_opposite]);
      if (next_area <= current_area) break;
      opposite = next_opposite;
    }
    detail::update_farthest(result, hull[i], hull[opposite]);
    detail::update_farthest(result, hull[next_i], hull[opposite]);
    const size_t next_opposite = (opposite + 1) % hull.size();
    const auto current_area = cross(hull[i], hull[next_i], hull[opposite]);
    const auto next_area = cross(hull[i], hull[next_i], hull[next_opposite]);
    if (sign<T>(next_area - current_area, epsilon) == 0) {
      detail::update_farthest(result, hull[i], hull[next_opposite]);
      detail::update_farthest(result, hull[next_i], hull[next_opposite]);
    }
  }
  return result;
}

// 点集凸包的最小宽度；少于三个非共线点时为 0。
inline f80 minimum_width(vector<Point> points, f80 epsilon = DEFAULT_EPS) {
  const vector<Point> hull = convex_hull(std::move(points), false, epsilon);
  if (hull.size() <= 2) return 0;
  f80 answer = std::numeric_limits<f80>::infinity();
  size_t opposite = 1;
  for (size_t i = 0; i < hull.size(); ++i) {
    const size_t next_i = (i + 1) % hull.size();
    const f80 edge_length = distance(hull[i], hull[next_i]);
    while (true) {
      const size_t next_opposite = (opposite + 1) % hull.size();
      const f80 current_area = cross(hull[i], hull[next_i], hull[opposite]);
      const f80 next_area = cross(hull[i], hull[next_i], hull[next_opposite]);
      const f80 comparison_tolerance =
          epsilon * edge_length +
          DEFAULT_RELATIVE_EPS * (std::abs(current_area) + std::abs(next_area));
      if (next_area <= current_area + comparison_tolerance) break;
      opposite = next_opposite;
    }
    answer = std::min(
        answer, cross(hull[i], hull[next_i], hull[opposite]) / edge_length);
  }
  return std::max(static_cast<f80>(0), answer);
}

namespace detail {

template <typename T>
void rotate_to_lowest(vector<Point2<T>>& polygon) {
  if (polygon.empty()) return;
  const auto iterator = std::min_element(
      polygon.begin(), polygon.end(),
      [](const Point2<T>& left, const Point2<T>& right) {
        return left.y < right.y || (!(right.y < left.y) && left.x < right.x);
      });
  std::rotate(polygon.begin(), iterator, polygon.end());
}

template <typename T>
void rotate_to_lexicographic_minimum(vector<Point2<T>>& polygon) {
  if (polygon.empty()) return;
  std::rotate(polygon.begin(), std::min_element(polygon.begin(), polygon.end()),
              polygon.end());
}

template <typename T>
int edge_half(const Point2<T>& from, const Point2<T>& to) noexcept {
  if (to.y != from.y) return to.y > from.y ? 0 : 1;
  return to.x >= from.x ? 0 : 1;
}

template <typename T>
Calculation<T> edge_cross(const Point2<T>& first, const Point2<T>& first_next,
                          const Point2<T>& second,
                          const Point2<T>& second_next) {
  using C = Calculation<T>;
  const C first_x = C(first_next.x) - C(first.x);
  const C first_y = C(first_next.y) - C(first.y);
  const C second_x = C(second_next.x) - C(second.x);
  const C second_y = C(second_next.y) - C(second.y);
  return first_x * second_y - first_y * second_x;
}

// 不把 EPS 放进方向比较器，保证比较关系传递。
template <typename T>
bool edge_direction_less(const Point2<T>& first, const Point2<T>& first_next,
                         const Point2<T>& second,
                         const Point2<T>& second_next) {
  const int first_half = edge_half(first, first_next);
  const int second_half = edge_half(second, second_next);
  if (first_half != second_half) return first_half < second_half;
  return edge_cross(first, first_next, second, second_next) > 0;
}

}  // namespace detail

// 两个严格凸包的线性闵可夫斯基和。输入不重复首点；大小 >= 3 时须为
// CCW 且无共线中间点。输出同样不重复首点。
template <typename T>
vector<Point2<T>> minkowski_sum_convex_ccw(vector<Point2<T>> first,
                                           vector<Point2<T>> second) {
  if (first.empty() || second.empty()) return {};
  if (first.size() == 1) {
    for (Point2<T>& point : second) {
      point = checked_add_point(point, first.front());
    }
    detail::rotate_to_lexicographic_minimum(second);
    return second;
  }
  if (second.size() == 1) {
    for (Point2<T>& point : first) {
      point = checked_add_point(point, second.front());
    }
    detail::rotate_to_lexicographic_minimum(first);
    return first;
  }

  detail::rotate_to_lowest(first);
  detail::rotate_to_lowest(second);
  vector<Point2<T>> result;
  if (first.size() > std::numeric_limits<size_t>::max() - second.size()) {
    throw std::length_error("Minkowski sum is too large");
  }
  result.reserve(first.size() + second.size());
  result.push_back(checked_add_point(first.front(), second.front()));
  size_t i = 0;
  size_t j = 0;
  while (i < first.size() || j < second.size()) {
    if (i == first.size()) {
      ++j;
    } else if (j == second.size()) {
      ++i;
    } else {
      const Point2<T>& first_current = first[i % first.size()];
      const Point2<T>& first_next = first[(i + 1) % first.size()];
      const Point2<T>& second_current = second[j % second.size()];
      const Point2<T>& second_next = second[(j + 1) % second.size()];
      if (detail::edge_direction_less(first_current, first_next, second_current,
                                      second_next)) {
        ++i;
      } else if (detail::edge_direction_less(second_current, second_next,
                                             first_current, first_next)) {
        ++j;
      } else {
        ++i;
        ++j;
      }
    }
    if (i != first.size() || j != second.size()) {
      result.push_back(checked_add_point(first[i % first.size()],
                                         second[j % second.size()]));
    }
  }
  detail::rotate_to_lexicographic_minimum(result);
  return result;
}

// 任意两个点集的凸包之闵可夫斯基和；含求凸包为
// O(n log n + m log m)，线性核心为 O(n + m)。
template <typename T>
vector<Point2<T>> minkowski_sum(vector<Point2<T>> first,
                                vector<Point2<T>> second,
                                f80 epsilon = DEFAULT_EPS) {
  first = convex_hull(std::move(first), false, epsilon);
  second = convex_hull(std::move(second), false, epsilon);
  return minkowski_sum_convex_ccw(std::move(first), std::move(second));
}

// 有向边 point + t * direction 的左侧（含边界）为半平面。
// direction 与 normal 均单位化，边界方程为 dot(normal, x) = offset。
struct HalfPlane {
  Point point;
  Point direction;
  Point normal;
  f80 offset;

  HalfPlane(Point boundary_point, Point boundary_direction,
            f80 epsilon = DEFAULT_EPS)
      : point(boundary_point) {
    if (!std::isfinite(point.x) || !std::isfinite(point.y) ||
        !std::isfinite(boundary_direction.x) ||
        !std::isfinite(boundary_direction.y) || !std::isfinite(epsilon) ||
        epsilon < 0) {
      throw std::invalid_argument("HalfPlane requires finite coordinates");
    }
    direction = unit(boundary_direction, epsilon);
    normal = perpendicular_left(direction);
    offset = dot(normal, point);
    if (!std::isfinite(offset)) {
      throw std::overflow_error("HalfPlane offset overflow");
    }
  }

  bool contains(const Point& candidate,
                f80 epsilon = DEFAULT_EPS) const noexcept {
    if (!std::isfinite(candidate.x) || !std::isfinite(candidate.y) ||
        !std::isfinite(epsilon) || epsilon < 0) {
      return false;
    }
    return dot(normal, candidate - point) >= -epsilon;
  }
};

inline HalfPlane half_plane_from_directed_edge(const Point& first,
                                               const Point& second,
                                               f80 epsilon = DEFAULT_EPS) {
  return HalfPlane(first, second - first, epsilon);
}

namespace detail {

inline optional<Point> intersect_half_plane_boundaries(
    const HalfPlane& first, const HalfPlane& second) {
  const f80 denominator = cross(first.direction, second.direction);
  if (directions_parallel(first.direction, second.direction, Tolerance{})) {
    return nullopt;
  }
  const f80 parameter =
      cross(second.point - first.point, second.direction) / denominator;
  const Point result = first.point + first.direction * parameter;
  if (!std::isfinite(result.x) || !std::isfinite(result.y)) return nullopt;
  return result;
}

// 增量法找可行点。若加入第 i 个约束后原可行点失效，则新可行点必可
// 在第 i 条边界上找到；把该边界参数化后，旧约束各贡献一个 t 区间。
inline optional<Point> half_plane_feasible_point(
    const vector<HalfPlane>& half_planes, f80 epsilon) {
  Point witness{};
  for (size_t i = 0; i < half_planes.size(); ++i) {
    if (half_planes[i].contains(witness, epsilon)) continue;

    f80 lower = -std::numeric_limits<f80>::infinity();
    f80 upper = std::numeric_limits<f80>::infinity();
    // contains 使用 signed_distance >= -epsilon，所以应参数化放宽后的
    // 边界；若仍用原边界，两个距离小于 epsilon 的近矛盾约束会误报空集。
    const Point base = half_planes[i].point - half_planes[i].normal * epsilon;
    const Point direction = half_planes[i].direction;
    for (size_t j = 0; j < i; ++j) {
      const f80 coefficient = dot(half_planes[j].normal, direction);
      const f80 value = dot(half_planes[j].normal, base - half_planes[j].point);
      if (std::abs(coefficient) <= DEFAULT_RELATIVE_EPS) {
        if (value < -epsilon) return nullopt;
        continue;
      }
      const f80 bound = (-epsilon - value) / coefficient;
      if (coefficient > 0) {
        lower = std::max(lower, bound);
      } else {
        upper = std::min(upper, bound);
      }
    }
    const f80 parameter_scale = std::max(
        {static_cast<f80>(1), std::isfinite(lower) ? std::abs(lower) : 0,
         std::isfinite(upper) ? std::abs(upper) : 0});
    const f80 roundoff =
        64 * std::numeric_limits<f80>::epsilon() * parameter_scale;
    if (lower > upper + roundoff) return nullopt;

    f80 parameter = 0;
    if (std::isfinite(lower) && std::isfinite(upper)) {
      parameter = lower / 2 + upper / 2;
    } else if (std::isfinite(lower)) {
      parameter = lower;
    } else if (std::isfinite(upper)) {
      parameter = upper;
    }
    witness = base + direction * parameter;
    if (!std::isfinite(witness.x) || !std::isfinite(witness.y)) {
      throw std::overflow_error("half-plane feasibility construction overflow");
    }
  }
  return witness;
}

// 存在非零 recession direction 当且仅当全部法向量落在某个闭半圆内。
inline bool half_plane_recession_is_unbounded(
    const vector<HalfPlane>& half_planes, [[maybe_unused]] f80 epsilon) {
  if (half_planes.empty()) return true;
  const f80 pi = std::numbers::pi_v<f80>;
  const f80 two_pi = 2 * pi;
  vector<f80> angles;
  angles.reserve(half_planes.size());
  for (const HalfPlane& half_plane : half_planes) {
    f80 angle = std::atan2(half_plane.normal.y, half_plane.normal.x);
    if (angle < 0) angle += two_pi;
    angles.push_back(angle);
  }
  std::sort(angles.begin(), angles.end());
  f80 maximum_gap = angles.front() + two_pi - angles.back();
  for (size_t i = 1; i < angles.size(); ++i) {
    maximum_gap = std::max(maximum_gap, angles[i] - angles[i - 1]);
  }
  // maximum_gap 是角度，不能加坐标空间的 distance epsilon。
  return maximum_gap + DEFAULT_RELATIVE_EPS >= pi;
}

// 标准双端队列半平面交。调用方已确认交集有界；正面积时 O(n log n)。
// 精确同向的边只保留更严格者，排序比较器中不使用 EPS。
inline optional<vector<Point>> bounded_half_plane_polygon_fast(
    vector<HalfPlane> half_planes, f80 epsilon) {
  struct AngledHalfPlane {
    f80 angle;
    HalfPlane half_plane;
  };

  const f80 two_pi = 2 * std::numbers::pi_v<f80>;
  vector<AngledHalfPlane> ordered;
  ordered.reserve(half_planes.size());
  for (HalfPlane& half_plane : half_planes) {
    f80 angle = std::atan2(half_plane.direction.y, half_plane.direction.x);
    if (angle < 0) angle += two_pi;
    ordered.push_back({angle, std::move(half_plane)});
  }
  std::sort(ordered.begin(), ordered.end(),
            [](const AngledHalfPlane& left, const AngledHalfPlane& right) {
              if (left.angle != right.angle) return left.angle < right.angle;
              return left.half_plane.offset > right.half_plane.offset;
            });

  vector<HalfPlane> unique;
  unique.reserve(ordered.size());
  for (const AngledHalfPlane& item : ordered) {
    if (!unique.empty() &&
        directions_parallel(unique.back().direction, item.half_plane.direction,
                            Tolerance{}) &&
        dot(unique.back().direction, item.half_plane.direction) > 0) {
      if (item.half_plane.offset > unique.back().offset) {
        unique.back() = item.half_plane;
      }
    } else {
      unique.push_back(item.half_plane);
    }
  }

  deque<HalfPlane> active;
  for (const HalfPlane& half_plane : unique) {
    while (active.size() >= 2) {
      const auto intersection = intersect_half_plane_boundaries(
          active[active.size() - 2], active.back());
      if (!intersection) return nullopt;
      if (half_plane.contains(*intersection, epsilon)) break;
      active.pop_back();
    }
    while (active.size() >= 2) {
      const auto intersection =
          intersect_half_plane_boundaries(active[0], active[1]);
      if (!intersection) return nullopt;
      if (half_plane.contains(*intersection, epsilon)) break;
      active.pop_front();
    }
    active.push_back(half_plane);
  }

  while (active.size() >= 3) {
    const auto intersection = intersect_half_plane_boundaries(
        active[active.size() - 2], active.back());
    if (!intersection) return nullopt;
    if (active.front().contains(*intersection, epsilon)) break;
    active.pop_back();
  }
  while (active.size() >= 3) {
    const auto intersection =
        intersect_half_plane_boundaries(active[0], active[1]);
    if (!intersection) return nullopt;
    if (active.back().contains(*intersection, epsilon)) break;
    active.pop_front();
  }
  if (active.size() < 3) return vector<Point>{};

  vector<Point> polygon;
  polygon.reserve(active.size());
  for (size_t i = 0; i < active.size(); ++i) {
    const auto intersection = intersect_half_plane_boundaries(
        active[i], active[(i + 1) % active.size()]);
    if (!intersection) return nullopt;
    polygon.push_back(*intersection);
  }
  for (const Point& point : polygon) {
    for (const HalfPlane& half_plane : unique) {
      if (!half_plane.contains(point, 8 * epsilon)) return nullopt;
    }
  }
  return convex_hull(std::move(polygon), false, epsilon);
}

// 仅在快算法无法表达零面积退化交集时使用；复杂度 O(n^3)。
inline vector<Point> bounded_half_plane_degenerate_vertices(
    const vector<HalfPlane>& half_planes, f80 epsilon) {
  vector<Point> candidates;
  for (size_t i = 0; i < half_planes.size(); ++i) {
    for (size_t j = i + 1; j < half_planes.size(); ++j) {
      const auto point =
          intersect_half_plane_boundaries(half_planes[i], half_planes[j]);
      if (!point) continue;
      bool feasible = true;
      for (const HalfPlane& half_plane : half_planes) {
        if (!half_plane.contains(*point, 8 * epsilon)) {
          feasible = false;
          break;
        }
      }
      if (feasible) candidates.push_back(*point);
    }
  }
  return convex_hull(std::move(candidates), false, 8 * epsilon);
}

}  // namespace detail

enum class HalfPlaneIntersectionType {
  Empty,
  Unbounded,
  BoundedPolygon,
  BoundedDegenerate
};

struct HalfPlaneIntersectionResult {
  HalfPlaneIntersectionType type = HalfPlaneIntersectionType::Empty;
  vector<Point> polygon;  // 多边形为 CCW；退化时可为一个点或一条线段。
  optional<Point> feasible_point;
};

// 已知交集有界且有正面积时的标准 O(n log n) 入口。成功返回 CCW 多边形；
// 空 vector 表示零面积/约束不足，nullopt 表示平行退化或数值构造失败。
inline optional<vector<Point>> half_plane_intersection_bounded(
    vector<HalfPlane> half_planes, f80 epsilon = DEFAULT_EPS) {
  if (!std::isfinite(epsilon) || epsilon < 0) {
    throw std::invalid_argument("epsilon must be finite and non-negative");
  }
  return detail::bounded_half_plane_polygon_fast(std::move(half_planes),
                                                 epsilon);
}

// 一般半平面交：区分空、无界、有界多边形和有界零面积交集。
// 可行性/有界性分类 O(n^2)，正面积多边形构造 O(n log n)；只有退化
// 回退会到 O(n^3)。空约束的交集为整个平面，故返回 Unbounded。
inline HalfPlaneIntersectionResult half_plane_intersection(
    const vector<HalfPlane>& half_planes, f80 epsilon = DEFAULT_EPS) {
  if (!std::isfinite(epsilon) || epsilon < 0) {
    throw std::invalid_argument("epsilon must be finite and non-negative");
  }
  const auto witness = detail::half_plane_feasible_point(half_planes, epsilon);
  if (!witness) return {};
  if (detail::half_plane_recession_is_unbounded(half_planes, epsilon)) {
    return {HalfPlaneIntersectionType::Unbounded, {}, witness};
  }

  auto polygon = detail::bounded_half_plane_polygon_fast(half_planes, epsilon);
  if (polygon && polygon->size() >= 3 &&
      polygon_area(*polygon) > epsilon * epsilon) {
    return {HalfPlaneIntersectionType::BoundedPolygon, std::move(*polygon),
            witness};
  }

  vector<Point> degenerate =
      detail::bounded_half_plane_degenerate_vertices(half_planes, epsilon);
  if (degenerate.empty()) degenerate.push_back(*witness);
  if (degenerate.size() >= 3 && polygon_area(degenerate) > epsilon * epsilon) {
    return {HalfPlaneIntersectionType::BoundedPolygon, std::move(degenerate),
            witness};
  }
  return {HalfPlaneIntersectionType::BoundedDegenerate, std::move(degenerate),
          witness};
}

// ---------- 三维计算几何 ----------
// 整数 dot/cross/triple 会先提升到 Calculation<T>；本模板中的 int256
// 足以覆盖完整 i64 坐标的三维点积、叉积和四点定向体积。
template <Coordinate T>
struct Point3 {
  T x{};
  T y{};
  T z{};

  constexpr Point3() = default;
  constexpr Point3(T x_value, T y_value, T z_value)
      : x(x_value), y(y_value), z(z_value) {}

  Point3 operator+() const noexcept { return *this; }

  Point3 operator-() const {
    if constexpr (is_bounded_integer_coordinate_v<T>) {
      return {checked_coordinate(-static_cast<Calculation<T>>(x)),
              checked_coordinate(-static_cast<Calculation<T>>(y)),
              checked_coordinate(-static_cast<Calculation<T>>(z))};
    } else {
      return {-x, -y, -z};
    }
  }

  Point3& operator+=(const Point3& other) {
    if constexpr (is_bounded_integer_coordinate_v<T>) {
      const T next_x =
          checked_coordinate(static_cast<Calculation<T>>(x) + other.x);
      const T next_y =
          checked_coordinate(static_cast<Calculation<T>>(y) + other.y);
      const T next_z =
          checked_coordinate(static_cast<Calculation<T>>(z) + other.z);
      x = next_x;
      y = next_y;
      z = next_z;
    } else {
      x += other.x;
      y += other.y;
      z += other.z;
    }
    return *this;
  }

  Point3& operator-=(const Point3& other) {
    if constexpr (is_bounded_integer_coordinate_v<T>) {
      const T next_x =
          checked_coordinate(static_cast<Calculation<T>>(x) - other.x);
      const T next_y =
          checked_coordinate(static_cast<Calculation<T>>(y) - other.y);
      const T next_z =
          checked_coordinate(static_cast<Calculation<T>>(z) - other.z);
      x = next_x;
      y = next_y;
      z = next_z;
    } else {
      x -= other.x;
      y -= other.y;
      z -= other.z;
    }
    return *this;
  }

  Point3& operator*=(T scalar) {
    if constexpr (is_bounded_integer_coordinate_v<T>) {
      const T next_x =
          checked_coordinate(static_cast<Calculation<T>>(x) * scalar);
      const T next_y =
          checked_coordinate(static_cast<Calculation<T>>(y) * scalar);
      const T next_z =
          checked_coordinate(static_cast<Calculation<T>>(z) * scalar);
      x = next_x;
      y = next_y;
      z = next_z;
    } else {
      x *= scalar;
      y *= scalar;
      z *= scalar;
    }
    return *this;
  }

  Point3& operator/=(T scalar) {
    if (scalar == T{}) {
      throw std::invalid_argument("Point3 division by zero");
    }
    if constexpr (is_bounded_integer_coordinate_v<T>) {
      const T next_x =
          checked_coordinate(static_cast<Calculation<T>>(x) / scalar);
      const T next_y =
          checked_coordinate(static_cast<Calculation<T>>(y) / scalar);
      const T next_z =
          checked_coordinate(static_cast<Calculation<T>>(z) / scalar);
      x = next_x;
      y = next_y;
      z = next_z;
    } else {
      x /= scalar;
      y /= scalar;
      z /= scalar;
    }
    return *this;
  }

  friend Point3 operator+(Point3 left, const Point3& right) {
    return left += right;
  }

  friend Point3 operator-(Point3 left, const Point3& right) {
    return left -= right;
  }

  friend Point3 operator*(Point3 point, T scalar) { return point *= scalar; }

  friend Point3 operator*(T scalar, Point3 point) { return point *= scalar; }

  friend Point3 operator/(Point3 point, T scalar) { return point /= scalar; }

  friend constexpr bool operator==(const Point3& left,
                                   const Point3& right) noexcept {
    return left.x == right.x && left.y == right.y && left.z == right.z;
  }

  friend constexpr bool operator!=(const Point3& left,
                                   const Point3& right) noexcept {
    return !(left == right);
  }

  friend constexpr bool operator<(const Point3& left,
                                  const Point3& right) noexcept {
    if (left.x != right.x) {
      return left.x < right.x;
    }
    if (left.y != right.y) {
      return left.y < right.y;
    }
    return left.z < right.z;
  }

 private:
  static T checked_coordinate(const Calculation<T>& value) {
    const Calculation<T> lowest =
        static_cast<Calculation<T>>(std::numeric_limits<T>::lowest());
    const Calculation<T> highest =
        static_cast<Calculation<T>>(std::numeric_limits<T>::max());
    if (value < lowest || value > highest) {
      throw std::overflow_error("Point3 coordinate arithmetic overflow");
    }
    return static_cast<T>(value);
  }
};

using Point3D = Point3<f80>;
using FPoint3 = Point3D;
using IPoint3 = Point3<i64>;
using IPoint3D = IPoint3;

template <typename T>
Calculation<T> dot(const Point3<T>& left, const Point3<T>& right) {
  using C = Calculation<T>;
  return static_cast<C>(left.x) * static_cast<C>(right.x) +
         static_cast<C>(left.y) * static_cast<C>(right.y) +
         static_cast<C>(left.z) * static_cast<C>(right.z);
}

// 对整数点返回 Point3<int256>，不会把叉积坐标窄化回 T。
template <typename T>
Point3<Calculation<T>> cross(const Point3<T>& left, const Point3<T>& right) {
  using C = Calculation<T>;
  const C lx = static_cast<C>(left.x);
  const C ly = static_cast<C>(left.y);
  const C lz = static_cast<C>(left.z);
  const C rx = static_cast<C>(right.x);
  const C ry = static_cast<C>(right.y);
  const C rz = static_cast<C>(right.z);
  return {ly * rz - lz * ry, lz * rx - lx * rz, lx * ry - ly * rx};
}

// (first-origin) cross (second-origin)，避免整数坐标先相减而溢出 T。
template <typename T>
Point3<Calculation<T>> cross(const Point3<T>& origin, const Point3<T>& first,
                             const Point3<T>& second) {
  using C = Calculation<T>;
  const C ax = static_cast<C>(first.x) - static_cast<C>(origin.x);
  const C ay = static_cast<C>(first.y) - static_cast<C>(origin.y);
  const C az = static_cast<C>(first.z) - static_cast<C>(origin.z);
  const C bx = static_cast<C>(second.x) - static_cast<C>(origin.x);
  const C by = static_cast<C>(second.y) - static_cast<C>(origin.y);
  const C bz = static_cast<C>(second.z) - static_cast<C>(origin.z);
  return {ay * bz - az * by, az * bx - ax * bz, ax * by - ay * bx};
}

template <typename T>
Calculation<T> triple(const Point3<T>& first, const Point3<T>& second,
                      const Point3<T>& third) {
  using C = Calculation<T>;
  const C ax = static_cast<C>(first.x);
  const C ay = static_cast<C>(first.y);
  const C az = static_cast<C>(first.z);
  const C bx = static_cast<C>(second.x);
  const C by = static_cast<C>(second.y);
  const C bz = static_cast<C>(second.z);
  const C cx = static_cast<C>(third.x);
  const C cy = static_cast<C>(third.y);
  const C cz = static_cast<C>(third.z);
  return ax * (by * cz - bz * cy) - ay * (bx * cz - bz * cx) +
         az * (bx * cy - by * cx);
}

// (first-origin) dot ((second-origin) cross (third-origin))。
template <typename T>
Calculation<T> triple(const Point3<T>& origin, const Point3<T>& first,
                      const Point3<T>& second, const Point3<T>& third) {
  using C = Calculation<T>;
  const C ax = static_cast<C>(first.x) - static_cast<C>(origin.x);
  const C ay = static_cast<C>(first.y) - static_cast<C>(origin.y);
  const C az = static_cast<C>(first.z) - static_cast<C>(origin.z);
  const C bx = static_cast<C>(second.x) - static_cast<C>(origin.x);
  const C by = static_cast<C>(second.y) - static_cast<C>(origin.y);
  const C bz = static_cast<C>(second.z) - static_cast<C>(origin.z);
  const C cx = static_cast<C>(third.x) - static_cast<C>(origin.x);
  const C cy = static_cast<C>(third.y) - static_cast<C>(origin.y);
  const C cz = static_cast<C>(third.z) - static_cast<C>(origin.z);
  return ax * (by * cz - bz * cy) - ay * (bx * cz - bz * cx) +
         az * (bx * cy - by * cx);
}

template <typename T>
Calculation<T> norm_squared(const Point3<T>& value) {
  return dot(value, value);
}

template <typename T>
Calculation<T> distance_squared(const Point3<T>& first,
                                const Point3<T>& second) {
  using C = Calculation<T>;
  const C dx = static_cast<C>(first.x) - static_cast<C>(second.x);
  const C dy = static_cast<C>(first.y) - static_cast<C>(second.y);
  const C dz = static_cast<C>(first.z) - static_cast<C>(second.z);
  return dx * dx + dy * dy + dz * dz;
}

template <typename T>
f80 length(const Point3<T>& value) noexcept {
  return std::hypotl(
      std::hypotl(static_cast<f80>(value.x), static_cast<f80>(value.y)),
      static_cast<f80>(value.z));
}

template <typename T>
f80 distance(const Point3<T>& first, const Point3<T>& second) noexcept {
  return std::hypotl(
      std::hypotl(static_cast<f80>(first.x) - static_cast<f80>(second.x),
                  static_cast<f80>(first.y) - static_cast<f80>(second.y)),
      static_cast<f80>(first.z) - static_cast<f80>(second.z));
}

inline bool is_finite(const Point3D& point) noexcept {
  return std::isfinite(point.x) && std::isfinite(point.y) &&
         std::isfinite(point.z);
}

inline bool almost_equal(const Point3D& left, const Point3D& right,
                         f80 epsilon = DEFAULT_EPS) noexcept {
  return distance(left, right) <= epsilon;
}

inline std::optional<Point3D> unit(const Point3D& vector,
                                   f80 epsilon = DEFAULT_EPS) {
  if (!is_finite(vector) || !std::isfinite(epsilon) || epsilon < 0) {
    return std::nullopt;
  }
  const f80 scale =
      std::max({std::abs(vector.x), std::abs(vector.y), std::abs(vector.z)});
  if (scale == 0) {
    return std::nullopt;
  }
  const Point3D scaled{vector.x / scale, vector.y / scale, vector.z / scale};
  const f80 normalized_length =
      std::hypotl(std::hypotl(scaled.x, scaled.y), scaled.z);
  if (!std::isfinite(normalized_length) ||
      scale <= epsilon / normalized_length) {
    return std::nullopt;
  }
  Point3D result = scaled / normalized_length;
  if (!is_finite(result)) {
    return std::nullopt;
  }
  return result;
}

struct Line3 {
  Point3D point{};
  Point3D direction{};  // 单位方向向量。
};

struct Plane3 {
  Point3D normal{};  // 单位法向量。
  f80 offset{};      // dot(normal, point) == offset。
};

inline bool is_valid(const Line3& line, f80 epsilon = DEFAULT_EPS) noexcept {
  if (!is_finite(line.point) || !is_finite(line.direction) ||
      !std::isfinite(epsilon) || epsilon < 0) {
    return false;
  }
  const f80 squared_length = static_cast<f80>(norm_squared(line.direction));
  const f80 invariant_epsilon = std::max(64 * epsilon, DEFAULT_RELATIVE_EPS);
  return std::isfinite(squared_length) &&
         std::abs(squared_length - 1) <= invariant_epsilon;
}

inline bool is_valid(const Plane3& plane, f80 epsilon = DEFAULT_EPS) noexcept {
  if (!is_finite(plane.normal) || !std::isfinite(plane.offset) ||
      !std::isfinite(epsilon) || epsilon < 0) {
    return false;
  }
  const f80 squared_length = static_cast<f80>(norm_squared(plane.normal));
  const f80 invariant_epsilon = std::max(64 * epsilon, DEFAULT_RELATIVE_EPS);
  return std::isfinite(squared_length) &&
         std::abs(squared_length - 1) <= invariant_epsilon;
}

// 工厂会拒绝非有限输入和退化方向，并把方向单位化。
inline std::optional<Line3> line3_from_point_direction(
    const Point3D& point, const Point3D& direction, f80 epsilon = DEFAULT_EPS) {
  if (!is_finite(point)) {
    return std::nullopt;
  }
  const auto normalized_direction = unit(direction, epsilon);
  if (!normalized_direction.has_value()) {
    return std::nullopt;
  }
  return Line3{point, *normalized_direction};
}

inline std::optional<Line3> line3_through(const Point3D& first,
                                          const Point3D& second,
                                          f80 epsilon = DEFAULT_EPS) {
  if (!is_finite(first) || !is_finite(second)) {
    return std::nullopt;
  }
  const Point3D direction = second - first;
  if (!is_finite(direction)) {
    return std::nullopt;
  }
  return line3_from_point_direction(first, direction, epsilon);
}

inline std::optional<Plane3> plane3_from_point_normal(
    const Point3D& point, const Point3D& normal, f80 epsilon = DEFAULT_EPS) {
  if (!is_finite(point)) {
    return std::nullopt;
  }
  const auto normalized_normal = unit(normal, epsilon);
  if (!normalized_normal.has_value()) {
    return std::nullopt;
  }
  const f80 offset = static_cast<f80>(dot(*normalized_normal, point));
  if (!std::isfinite(offset)) {
    return std::nullopt;
  }
  return Plane3{*normalized_normal, offset};
}

inline std::optional<Plane3> plane3_through(const Point3D& first,
                                            const Point3D& second,
                                            const Point3D& third,
                                            f80 epsilon = DEFAULT_EPS) {
  if (!is_finite(first) || !is_finite(second) || !is_finite(third)) {
    return std::nullopt;
  }
  const Point3D first_edge = second - first;
  const Point3D second_edge = third - first;
  if (!is_finite(first_edge) || !is_finite(second_edge)) {
    return std::nullopt;
  }
  const Point3D normal = cross(first_edge, second_edge);
  return plane3_from_point_normal(first, normal, epsilon);
}

inline Point3D point_at(const Line3& line, f80 parameter,
                        f80 epsilon = DEFAULT_EPS) {
  if (!is_valid(line, epsilon) || !std::isfinite(parameter)) {
    throw std::invalid_argument("invalid 3D line or parameter");
  }
  const Point3D result = line.point + line.direction * parameter;
  if (!is_finite(result)) {
    throw std::overflow_error("non-finite point on 3D line");
  }
  return result;
}

inline Point3D projection(const Point3D& point, const Line3& line,
                          f80 epsilon = DEFAULT_EPS) {
  if (!is_finite(point) || !is_valid(line, epsilon)) {
    throw std::invalid_argument("invalid point or 3D line");
  }
  const f80 parameter =
      static_cast<f80>(dot(point - line.point, line.direction));
  return point_at(line, parameter, epsilon);
}

inline f80 distance_to_line(const Point3D& point, const Line3& line,
                            f80 epsilon = DEFAULT_EPS) {
  return distance(point, projection(point, line, epsilon));
}

inline f80 signed_distance_to_plane(const Point3D& point, const Plane3& plane,
                                    f80 epsilon = DEFAULT_EPS) {
  if (!is_finite(point) || !is_valid(plane, epsilon)) {
    throw std::invalid_argument("invalid point or 3D plane");
  }
  return static_cast<f80>(dot(plane.normal, point)) - plane.offset;
}

inline f80 distance_to_plane(const Point3D& point, const Plane3& plane,
                             f80 epsilon = DEFAULT_EPS) {
  return std::abs(signed_distance_to_plane(point, plane, epsilon));
}

inline Point3D projection(const Point3D& point, const Plane3& plane,
                          f80 epsilon = DEFAULT_EPS) {
  const f80 signed_distance = signed_distance_to_plane(point, plane, epsilon);
  const Point3D result = point - plane.normal * signed_distance;
  if (!is_finite(result)) {
    throw std::overflow_error("non-finite projection on 3D plane");
  }
  return result;
}

enum class LineLineRelation3 { UniqueClosestPair, Parallel, Coincident };

struct ClosestLinePoints3Result {
  LineLineRelation3 relation = LineLineRelation3::UniqueClosestPair;
  Point3D first_point{};
  Point3D second_point{};
  f80 first_parameter{};
  f80 second_parameter{};
  f80 distance{};
};

inline ClosestLinePoints3Result closest_points(const Line3& first,
                                               const Line3& second,
                                               f80 epsilon = DEFAULT_EPS) {
  if (!is_valid(first, epsilon) || !is_valid(second, epsilon)) {
    throw std::invalid_argument("invalid 3D line");
  }
  const Point3D difference = first.point - second.point;
  const f80 a = static_cast<f80>(dot(first.direction, first.direction));
  const f80 b = static_cast<f80>(dot(first.direction, second.direction));
  const f80 c = static_cast<f80>(dot(second.direction, second.direction));
  const f80 d = static_cast<f80>(dot(first.direction, difference));
  const f80 e = static_cast<f80>(dot(second.direction, difference));
  const f80 denominator = a * c - b * b;

  ClosestLinePoints3Result result;
  if (std::abs(denominator) <=
      DEFAULT_RELATIVE_EPS * DEFAULT_RELATIVE_EPS * a * c) {
    result.first_parameter = 0;
    result.second_parameter = e / c;
    result.first_point = first.point;
    result.second_point = point_at(second, result.second_parameter, epsilon);
    result.distance = distance(result.first_point, result.second_point);
    result.relation = result.distance <= epsilon ? LineLineRelation3::Coincident
                                                 : LineLineRelation3::Parallel;
    return result;
  }

  result.first_parameter = (b * e - c * d) / denominator;
  result.second_parameter = (a * e - b * d) / denominator;
  result.first_point = point_at(first, result.first_parameter, epsilon);
  result.second_point = point_at(second, result.second_parameter, epsilon);
  result.distance = distance(result.first_point, result.second_point);
  result.relation = LineLineRelation3::UniqueClosestPair;
  if (!std::isfinite(result.distance)) {
    throw std::overflow_error("non-finite distance between 3D lines");
  }
  return result;
}

inline f80 distance_between_lines(const Line3& first, const Line3& second,
                                  f80 epsilon = DEFAULT_EPS) {
  return closest_points(first, second, epsilon).distance;
}

enum class LinePlaneIntersectionType3 { None, SinglePoint, Contained };

struct LinePlaneIntersection3 {
  LinePlaneIntersectionType3 type = LinePlaneIntersectionType3::None;
  Point3D point{};
  f80 line_parameter{};
};

inline LinePlaneIntersection3 intersect(const Line3& line, const Plane3& plane,
                                        f80 epsilon = DEFAULT_EPS) {
  if (!is_valid(line, epsilon) || !is_valid(plane, epsilon)) {
    throw std::invalid_argument("invalid 3D line or plane");
  }
  const f80 denominator = static_cast<f80>(dot(plane.normal, line.direction));
  const f80 numerator =
      plane.offset - static_cast<f80>(dot(plane.normal, line.point));
  if (std::abs(denominator) <= DEFAULT_RELATIVE_EPS) {
    return {std::abs(numerator) <= epsilon
                ? LinePlaneIntersectionType3::Contained
                : LinePlaneIntersectionType3::None,
            {},
            0};
  }
  const f80 parameter = numerator / denominator;
  return {LinePlaneIntersectionType3::SinglePoint,
          point_at(line, parameter, epsilon), parameter};
}

enum class PlanePlaneIntersectionType3 { None, SingleLine, Coincident };

struct PlanePlaneIntersection3 {
  PlanePlaneIntersectionType3 type = PlanePlaneIntersectionType3::None;
  Line3 line{};
};

inline PlanePlaneIntersection3 intersect(const Plane3& first,
                                         const Plane3& second,
                                         f80 epsilon = DEFAULT_EPS) {
  if (!is_valid(first, epsilon) || !is_valid(second, epsilon)) {
    throw std::invalid_argument("invalid 3D plane");
  }
  const Point3D direction = cross(first.normal, second.normal);
  const f80 direction_squared = static_cast<f80>(norm_squared(direction));
  if (direction_squared <= DEFAULT_RELATIVE_EPS * DEFAULT_RELATIVE_EPS) {
    const f80 orientation = static_cast<f80>(dot(first.normal, second.normal));
    const f80 aligned_second_offset =
        orientation >= 0 ? second.offset : -second.offset;
    return {std::abs(first.offset - aligned_second_offset) <= epsilon
                ? PlanePlaneIntersectionType3::Coincident
                : PlanePlaneIntersectionType3::None,
            {}};
  }

  // x = (c1 * (n2 x d) + c2 * (d x n1)) / |d|^2。
  const Point3D point = (cross(second.normal, direction) * first.offset +
                         cross(direction, first.normal) * second.offset) /
                        direction_squared;
  const auto line = line3_from_point_direction(point, direction, epsilon);
  if (!line.has_value()) {
    throw std::overflow_error("failed to construct plane intersection line");
  }
  return {PlanePlaneIntersectionType3::SingleLine, *line};
}

template <typename T>
f80 triangle_area(const Point3<T>& first, const Point3<T>& second,
                  const Point3<T>& third) {
  using C = Calculation<T>;
  const C ax = static_cast<C>(second.x) - static_cast<C>(first.x);
  const C ay = static_cast<C>(second.y) - static_cast<C>(first.y);
  const C az = static_cast<C>(second.z) - static_cast<C>(first.z);
  const C bx = static_cast<C>(third.x) - static_cast<C>(first.x);
  const C by = static_cast<C>(third.y) - static_cast<C>(first.y);
  const C bz = static_cast<C>(third.z) - static_cast<C>(first.z);
  const C cx = ay * bz - az * by;
  const C cy = az * bx - ax * bz;
  const C cz = ax * by - ay * bx;
  // 不在 int256 内平方叉积分量，避免完整 i64 输入的中间值超界。
  return std::hypotl(std::hypotl(static_cast<f80>(cx), static_cast<f80>(cy)),
                     static_cast<f80>(cz)) /
         2;
}

template <typename T>
Calculation<T> tetrahedron_signed_six_volume(const Point3<T>& first,
                                             const Point3<T>& second,
                                             const Point3<T>& third,
                                             const Point3<T>& fourth) {
  return triple(first, second, third, fourth);
}

template <typename T>
f80 tetrahedron_volume(const Point3<T>& first, const Point3<T>& second,
                       const Point3<T>& third, const Point3<T>& fourth) {
  const Calculation<T> signed_six_volume =
      tetrahedron_signed_six_volume(first, second, third, fourth);
  return std::abs(static_cast<f80>(signed_six_volume)) / 6;
}

struct Sphere3 {
  Point3D center{};
  f80 radius{};
};

// 四面体外接球；四点非有限或近共面时返回 nullopt。
inline std::optional<Sphere3> circumsphere(const Point3D& first,
                                           const Point3D& second,
                                           const Point3D& third,
                                           const Point3D& fourth,
                                           f80 epsilon = DEFAULT_EPS) {
  if (!is_finite(first) || !is_finite(second) || !is_finite(third) ||
      !is_finite(fourth) || !std::isfinite(epsilon) || epsilon < 0) {
    return std::nullopt;
  }
  const Point3D a = second - first;
  const Point3D b = third - first;
  const Point3D c = fourth - first;
  if (!is_finite(a) || !is_finite(b) || !is_finite(c)) {
    return std::nullopt;
  }
  const f80 a_length = length(a);
  const f80 b_length = length(b);
  const f80 c_length = length(c);
  const f80 scale = a_length * b_length * c_length;
  const f80 determinant = static_cast<f80>(triple(a, b, c));
  if (!std::isfinite(scale) || !std::isfinite(determinant) || scale == 0 ||
      std::abs(determinant) <= epsilon * scale) {
    return std::nullopt;
  }
  const f80 a_squared = static_cast<f80>(norm_squared(a));
  const f80 b_squared = static_cast<f80>(norm_squared(b));
  const f80 c_squared = static_cast<f80>(norm_squared(c));
  const Point3D relative_center =
      (cross(b, c) * a_squared + cross(c, a) * b_squared +
       cross(a, b) * c_squared) /
      (2 * determinant);
  const Point3D center = first + relative_center;
  const f80 radius = distance(center, first);
  if (!is_finite(center) || !std::isfinite(radius)) {
    return std::nullopt;
  }
  return Sphere3{center, radius};
}

}  // namespace geometry

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

template <typename T>
concept Coefficient = is_coefficient_v<std::remove_cv_t<T>>;

consteval std::uint32_t pow_mod_u32(std::uint32_t base, std::uint64_t exponent,
                                    std::uint32_t modulus) {
  std::uint64_t result = 1 % modulus;
  std::uint64_t value = base % modulus;
  while (exponent > 0) {
    if (exponent & 1) result = result * value % modulus;
    value = value * value % modulus;
    exponent >>= 1;
  }
  return static_cast<std::uint32_t>(result);
}

consteval bool is_prime_u32(std::uint32_t value) {
  if (value < 2) return false;
  if ((value & 1U) == 0) return value == 2;
  for (std::uint32_t divisor = 3; divisor <= value / divisor; divisor += 2) {
    if (value % divisor == 0) return false;
  }
  return true;
}

consteval bool is_primitive_root_u32(std::uint32_t root, std::uint32_t prime) {
  if (!is_prime_u32(prime) || root == 0 || root >= prime) return false;
  const std::uint32_t phi = prime - 1;
  std::uint32_t remaining = phi;
  for (std::uint32_t factor = 2; factor <= remaining / factor; ++factor) {
    if (remaining % factor != 0) continue;
    if (pow_mod_u32(root, phi / factor, prime) == 1) return false;
    do {
      remaining /= factor;
    } while (remaining % factor == 0);
  }
  if (remaining > 1 && pow_mod_u32(root, phi / remaining, prime) == 1) {
    return false;
  }
  return true;
}

constexpr std::size_t FFT_SAFE_MAX_LENGTH = std::size_t{1} << 20;
constexpr u128 FFT_SAFE_INTEGER_BOUND =
    static_cast<u128>(1'000'000'000'000'000ULL);

template <Coefficient T>
u64 magnitude(T value) {
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
  if (result_size > std::bit_floor(std::numeric_limits<std::size_t>::max())) {
    throw std::length_error("transform length overflow");
  }
  return std::bit_ceil(result_size);
}

template <Coefficient T>
u64 normalize_mod(T value, u64 modulus) {
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
  while (result > 0 && static_cast<u128>(result - 1) * (result - 1) >= value) {
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
  if (!std::has_single_bit(size)) {
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
  static constexpr FFTReal pi = std::numbers::pi_v<FFTReal>;
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
        const FFTComplex odd = values[left + i + half] * roots[half + i];
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
template <detail::Coefficient A, detail::Coefficient B>
[[nodiscard]] std::vector<i64> convolution_fft(const std::vector<A>& a,
                                               const std::vector<B>& b) {
  const std::size_t result_size = detail::convolution_size(a.size(), b.size());
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
  static_assert(detail::is_prime_u32(Mod), "NTT modulus must be prime");
  static_assert(
      detail::is_primitive_root_u32(PrimitiveRoot, Mod),
      "NTT PrimitiveRoot must generate the full multiplicative group");
  static_assert(MaxPower > 0 &&
                MaxPower < std::numeric_limits<std::size_t>::digits);

 public:
  static constexpr std::uint32_t modulus = Mod;
  static constexpr std::size_t max_length = std::size_t{1} << MaxPower;
  static_assert((static_cast<u64>(Mod) - 1) % max_length == 0);

  static void transform(std::vector<std::uint32_t>& values, bool inverse) {
    const std::size_t size = values.size();
    if (size == 0) return;
    if (!std::has_single_bit(size)) {
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

    static constexpr auto stage_values = [] {
      std::array<
          std::array<std::uint32_t, static_cast<std::size_t>(MaxPower) + 1>, 3>
          result{};
      result[2][0] = 1;
      for (std::size_t level = 1; level <= static_cast<std::size_t>(MaxPower);
           ++level) {
        const std::uint64_t length = std::uint64_t{1} << level;
        result[0][level] = detail::pow_mod_u32(
            PrimitiveRoot, (static_cast<std::uint64_t>(Mod) - 1) / length, Mod);
        result[1][level] = detail::pow_mod_u32(result[0][level], Mod - 2, Mod);
        result[2][level] = detail::pow_mod_u32(
            static_cast<std::uint32_t>(length % Mod), Mod - 2, Mod);
      }
      return result;
    }();

    for (std::size_t length = 2; length <= size; length <<= 1) {
      const std::size_t level =
          static_cast<std::size_t>(std::countr_zero(length));
      const u64 root = stage_values[inverse ? 1 : 0][level];
      const std::size_t half = length >> 1;
      for (std::size_t left = 0; left < size; left += length) {
        u64 power = 1;
        for (std::size_t i = 0; i < half; ++i) {
          const std::uint32_t even = values[left + i];
          const std::uint32_t odd = static_cast<std::uint32_t>(
              static_cast<u64>(values[left + i + half]) * power % Mod);
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
      const std::size_t level =
          static_cast<std::size_t>(std::bit_width(size) - 1);
      const u64 inverse_size = stage_values[2][level];
      for (std::uint32_t& value : values) {
        value = static_cast<std::uint32_t>(static_cast<u64>(value) *
                                           inverse_size % Mod);
      }
    }
  }

  template <detail::Coefficient A, detail::Coefficient B>
  [[nodiscard]] static std::vector<std::uint32_t> convolution(
      const std::vector<A>& a, const std::vector<B>& b) {
    const std::size_t result_size =
        detail::convolution_size(a.size(), b.size());
    if (result_size == 0) return {};
    const std::size_t size = detail::transform_size(result_size);
    if (size > max_length) {
      throw std::length_error("NTT convolution is too long");
    }

    std::vector<std::uint32_t> fa(size), fb(size);
    for (std::size_t i = 0; i < a.size(); ++i) {
      fa[i] = static_cast<std::uint32_t>(detail::normalize_mod(a[i], Mod));
    }
    for (std::size_t i = 0; i < b.size(); ++i) {
      fb[i] = static_cast<std::uint32_t>(detail::normalize_mod(b[i], Mod));
    }
    transform(fa, false);
    transform(fb, false);
    for (std::size_t i = 0; i < size; ++i) {
      fa[i] = static_cast<std::uint32_t>(static_cast<u64>(fa[i]) * fb[i] % Mod);
    }
    transform(fa, true);
    fa.resize(result_size);
    return fa;
  }
};

using NTT998244353 = NTT<998'244'353U, 3U, 23>;

template <detail::Coefficient A, detail::Coefficient B>
[[nodiscard]] std::vector<std::uint32_t> convolution_ntt(
    const std::vector<A>& a, const std::vector<B>& b) {
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

inline u64 crt_first_two(std::uint32_t residue1,
                         std::uint32_t residue2) noexcept {
  u64 step1 =
      (static_cast<u64>(residue2) + MTT_P2 - residue1 % MTT_P2) % MTT_P2;
  step1 = step1 * MTT_INV_P1_MOD_P2 % MTT_P2;
  return static_cast<u64>(residue1) + static_cast<u64>(MTT_P1) * step1;
}

inline u128 crt_add_third(u64 value12, std::uint32_t residue3) noexcept {
  u64 step2 = (static_cast<u64>(residue3) + MTT_P3 - value12 % MTT_P3) % MTT_P3;
  step2 = step2 * MTT_INV_P1P2_MOD_P3 % MTT_P3;
  return static_cast<u128>(value12) + static_cast<u128>(MTT_P1P2) * step2;
}

}  // namespace detail

// MTT：三组 NTT + CRT，对任意 1 <= modulus <= INT_MAX（不要求质数）
// 精确计算模卷积。公共代数长度上限 2^24；CRT 分两阶段合并并复用第三
// 个剩余数组作为输出，避免同时保留三份剩余数组和一份最终结果。
template <detail::Coefficient A, detail::Coefficient B>
[[nodiscard]] std::vector<std::uint32_t> convolution_mtt(
    const std::vector<A>& a, const std::vector<B>& b, i64 modulus) {
  if (modulus <= 0 || static_cast<u64>(modulus) > detail::MTT_MAX_MODULUS) {
    throw std::invalid_argument("MTT requires 1 <= modulus <= INT_MAX");
  }
  const std::size_t result_size = detail::convolution_size(a.size(), b.size());
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

  auto residue1 = detail::MTTN1::convolution(normalized_a, normalized_b);
  auto residue2 = detail::MTTN2::convolution(normalized_a, normalized_b);
  std::vector<u64> residue12(result_size);
  for (std::size_t i = 0; i < result_size; ++i) {
    residue12[i] = detail::crt_first_two(residue1[i], residue2[i]);
  }
  std::vector<std::uint32_t>().swap(residue1);
  std::vector<std::uint32_t>().swap(residue2);

  auto result = detail::MTTN3::convolution(normalized_a, normalized_b);
  for (std::size_t i = 0; i < result_size; ++i) {
    result[i] = static_cast<std::uint32_t>(
        detail::crt_add_third(residue12[i], result[i]) % mod);
  }
  return result;
}

// 拆系数 FFT：令 B=ceil(sqrt(modulus))，把 x 拆成 low+B*high。
// 支持任意 1 <= modulus <= INT_MAX（不要求质数），但仍是浮点算法。
// 为控制误差，限制变换长度 <= 2^20，且三个子卷积的粗界 <= 1e15；
// 超出时抛异常，请改用精确的 convolution_mtt。
template <detail::Coefficient A, detail::Coefficient B>
[[nodiscard]] std::vector<std::uint32_t> convolution_split_fft(
    const std::vector<A>& a, const std::vector<B>& b, i64 modulus) {
  if (modulus <= 0 || static_cast<u64>(modulus) > detail::MTT_MAX_MODULUS) {
    throw std::invalid_argument("split FFT requires 1 <= modulus <= INT_MAX");
  }
  const std::size_t result_size = detail::convolution_size(a.size(), b.size());
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
    fa[i] = FFTComplex(static_cast<FFTReal>(low), static_cast<FFTReal>(high));
  }
  for (std::size_t i = 0; i < b.size(); ++i) {
    const u64 value = detail::normalize_mod(b[i], mod);
    const u64 low = value % base;
    const u64 high = value / base;
    max_b_low = std::max(max_b_low, low);
    max_b_high = std::max(max_b_high, high);
    fb[i] = FFTComplex(static_cast<FFTReal>(low), static_cast<FFTReal>(high));
  }

  const u128 terms = static_cast<u128>(std::min(a.size(), b.size()));
  const u128 bound_low = terms * max_a_low * max_b_low;
  const u128 bound_high = terms * max_a_high * max_b_high;
  const u128 bound_cross = terms * (static_cast<u128>(max_a_low) * max_b_high +
                                    static_cast<u128>(max_a_high) * max_b_low);
  if (bound_low > detail::FFT_SAFE_INTEGER_BOUND ||
      bound_high > detail::FFT_SAFE_INTEGER_BOUND ||
      bound_cross > detail::FFT_SAFE_INTEGER_BOUND) {
    throw std::overflow_error("split FFT precision bound exceeded; use MTT");
  }

  fft(fa, false);
  fft(fb, false);
  const FFTComplex minus_half_i(0, -0.5L);
  const FFTComplex plus_i(0, 1);
  for (std::size_t i = 0; i < size; ++i) {
    const std::size_t mirror = (size - i) & (size - 1);
    if (i > mirror) continue;

    const FFTComplex a_low = (fa[i] + std::conj(fa[mirror])) * 0.5L;
    const FFTComplex a_high = (fa[i] - std::conj(fa[mirror])) * minus_half_i;
    const FFTComplex b_low = (fb[i] + std::conj(fb[mirror])) * 0.5L;
    const FFTComplex b_high = (fb[i] - std::conj(fb[mirror])) * minus_half_i;
    const FFTComplex low_product = a_low * b_low;
    const FFTComplex high_product = a_high * b_high;
    const FFTComplex cross_product = a_low * b_high + a_high * b_low;

    fa[i] = low_product + plus_i * high_product;
    fb[i] = cross_product;
    if (i != mirror) {
      fa[mirror] = std::conj(low_product) + plus_i * std::conj(high_product);
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

template <FWTType Type>
concept ValidFWTType =
    Type == FWTType::Or || Type == FWTType::And || Type == FWTType::Xor;

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

inline std::size_t mask_bits(std::size_t size) {
  if (size == 0) return 0;
  if (!std::has_single_bit(size)) {
    throw std::invalid_argument("FWT/FMT length must be a power of two");
  }
  return static_cast<std::size_t>(std::bit_width(size) - 1);
}

inline std::size_t require_same_mask_shape(std::size_t a_size,
                                           std::size_t b_size) {
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

template <FWTType Type>
  requires ValidFWTType<Type>
inline void fwt_core(std::vector<u64>& values, bool inverse, u64 modulus,
                     std::size_t bits) {
  for (u64& value : values) value %= modulus;
  if (values.empty()) return;

  for (std::size_t half = 1; half < values.size(); half <<= 1) {
    for (std::size_t left = 0; left < values.size(); left += half << 1) {
      for (std::size_t i = 0; i < half; ++i) {
        u64& lower = values[left + i];
        u64& upper = values[left + i + half];
        if constexpr (Type == FWTType::Or) {
          upper = inverse ? sub_mod(upper, lower, modulus)
                          : add_mod(upper, lower, modulus);
        } else if constexpr (Type == FWTType::And) {
          lower = inverse ? sub_mod(lower, upper, modulus)
                          : add_mod(lower, upper, modulus);
        } else {
          const u64 sum = add_mod(lower, upper, modulus);
          const u64 difference = sub_mod(lower, upper, modulus);
          lower = sum;
          upper = difference;
        }
      }
    }
  }

  if constexpr (Type == FWTType::Xor) {
    if (inverse && bits > 0) {
      const u64 inverse_two = modulus / 2 + 1;
      u64 inverse_size = 1 % modulus;
      for (std::size_t i = 0; i < bits; ++i) {
        inverse_size = ::mul_mod(inverse_size, inverse_two, modulus);
      }
      for (u64& value : values) {
        value = ::mul_mod(value, inverse_size, modulus);
      }
    }
  }
}

}  // namespace detail

// 原地 FWT。values 是 u64，会先按 modulus 归一化；参数错误时不修改。
// OR/AND 在任意正模下均可逆；XOR 长度 > 1 时逆变换要求奇数模。
template <FWTType Type>
  requires detail::ValidFWTType<Type>
inline void fwt(std::vector<u64>& values, bool inverse, i64 modulus) {
  const u64 mod = detail::checked_fwt_modulus(modulus);
  const std::size_t bits = detail::mask_bits(values.size());
  if constexpr (Type == FWTType::Xor) {
    if (inverse) detail::require_xor_inverse(values.size(), Type, mod);
  }
  detail::fwt_core<Type>(values, inverse, mod, bits);
}

inline void fwt(std::vector<u64>& values, FWTType type, bool inverse,
                i64 modulus) {
  const u64 mod = detail::checked_fwt_modulus(modulus);
  detail::require_fwt_type(type);
  const std::size_t bits = detail::mask_bits(values.size());
  if (inverse) detail::require_xor_inverse(values.size(), type, mod);
  switch (type) {
    case FWTType::Or:
      return detail::fwt_core<FWTType::Or>(values, inverse, mod, bits);
    case FWTType::And:
      return detail::fwt_core<FWTType::And>(values, inverse, mod, bits);
    case FWTType::Xor:
      return detail::fwt_core<FWTType::Xor>(values, inverse, mod, bits);
  }
  std::unreachable();
}

inline void fwt_or(std::vector<u64>& values, bool inverse, i64 modulus) {
  fwt<FWTType::Or>(values, inverse, modulus);
}

inline void fwt_and(std::vector<u64>& values, bool inverse, i64 modulus) {
  fwt<FWTType::And>(values, inverse, modulus);
}

inline void fwt_xor(std::vector<u64>& values, bool inverse, i64 modulus) {
  fwt<FWTType::Xor>(values, inverse, modulus);
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
template <detail::Coefficient A, detail::Coefficient B>
[[nodiscard]] std::vector<u64> convolution_fwt(const std::vector<A>& a,
                                               const std::vector<B>& b,
                                               FWTType type, i64 modulus) {
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

template <detail::Coefficient A, detail::Coefficient B>
[[nodiscard]] std::vector<u64> convolution_fwt_or(const std::vector<A>& a,
                                                  const std::vector<B>& b,
                                                  i64 modulus) {
  return convolution_fwt(a, b, FWTType::Or, modulus);
}

template <detail::Coefficient A, detail::Coefficient B>
[[nodiscard]] std::vector<u64> convolution_fwt_and(const std::vector<A>& a,
                                                   const std::vector<B>& b,
                                                   i64 modulus) {
  return convolution_fwt(a, b, FWTType::And, modulus);
}

template <detail::Coefficient A, detail::Coefficient B>
[[nodiscard]] std::vector<u64> convolution_fwt_xor(const std::vector<A>& a,
                                                   const std::vector<B>& b,
                                                   i64 modulus) {
  return convolution_fwt(a, b, FWTType::Xor, modulus);
}

// 标准子集卷积：result[S] = sum_{T subseteq S} a[T] * b[S\T]。
// 设 n=2^k，复杂度 O(k^2*2^k)，额外空间 O(k*2^k)；任意正模可用。
// 当前 u64 实现 k=20 时约需 350 MiB，需结合题目内存限制使用。
template <detail::Coefficient A, detail::Coefficient B>
[[nodiscard]] std::vector<u64> convolution_subset(const std::vector<A>& a,
                                                  const std::vector<B>& b,
                                                  i64 modulus) {
  const u64 mod = detail::checked_fwt_modulus(modulus);
  const std::size_t bits = detail::require_same_mask_shape(a.size(), b.size());
  if (a.empty()) return {};
  if (mod == 1) return std::vector<u64>(a.size(), 0);

  std::vector<unsigned char> rank(a.size());
  std::vector<std::vector<u64>> ranked_a(bits + 1, std::vector<u64>(a.size()));
  std::vector<std::vector<u64>> ranked_b(bits + 1, std::vector<u64>(a.size()));
  for (std::size_t mask = 0; mask < a.size(); ++mask) {
    rank[mask] = static_cast<unsigned char>(bitop::popcount(mask));
    ranked_a[rank[mask]][mask] = detail::normalize_mod(a[mask], mod);
    ranked_b[rank[mask]][mask] = detail::normalize_mod(b[mask], mod);
  }
  for (std::size_t current_rank = 0; current_rank <= bits; ++current_rank) {
    subset_zeta_transform(ranked_a[current_rank], modulus);
    subset_zeta_transform(ranked_b[current_rank], modulus);
  }

  std::vector<u64> result(a.size());
  std::vector<u64> layer(a.size());
  for (std::size_t current_rank = 0; current_rank <= bits; ++current_rank) {
    for (std::size_t mask = 0; mask < a.size(); ++mask) {
      u64 value = 0;
      for (std::size_t left_rank = 0; left_rank <= current_rank; ++left_rank) {
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

int main() {
  ios_base::sync_with_stdio(false);
  cin.tie(nullptr);
  ll T = 1LL;
  // cin >> T;
  while (T--) solve();
  return 0;
}
