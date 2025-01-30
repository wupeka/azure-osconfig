#ifndef TYPE_TRAITS_HPP
#define TYPE_TRAITS_HPP

#include <type_traits>

namespace compliance
{
    template <typename T>
    constexpr bool noexcept_copyable() noexcept
    {
        return noexcept(std::is_copy_constructible<T>::value);
    }

    template <typename T>
    constexpr bool noexcept_movable() noexcept
    {
        return noexcept(std::is_move_constructible<T>::value);
    }
} // namespace compliance

#endif // TYPE_TRAITS_HPP
