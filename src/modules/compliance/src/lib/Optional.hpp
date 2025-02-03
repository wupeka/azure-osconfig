#ifndef OPTIONAL_HPP
#define OPTIONAL_HPP

#include "TypeTraits.hpp"
#include <memory>

namespace compliance
{
    template<typename T>
    class Optional
    {
        std::unique_ptr<T> mValue = nullptr;
    public:
        Optional() = default;
        Optional(T value)
        {
            mValue.reset(new T(std::move(value)));
        }

        Optional(const Optional& other)
        {
            if (other.mValue != nullptr)
            {
                mValue.reset(new T(*other.mValue));
            }
            else
            {
                mValue.reset();
            }
        }

        Optional(Optional&& other) noexcept
        {
            mValue = std::move(other.mValue);
        }

        Optional& operator=(const Optional& other)
        {
            if (this == &other)
            {
                return *this;
            }

            if (other.mValue != nullptr)
            {
                mValue.reset(new T(*other.mValue));
            }
            else
            {
                mValue.reset();
            }

            return *this;
        }

        Optional& operator=(T value)
        {
            if( mValue != nullptr )
            {
                *mValue = std::move(value);
            }
            else
            {
                mValue.reset(new T(std::move(value)));
            }
            return *this;
        }

        Optional& operator=(Optional&& other) noexcept
        {
            if (this == &other)
            {
                return *this;
            }

            mValue = std::move(other.mValue);
            return *this;
        }

        bool has_value() const
        {
            return mValue != nullptr;
        }

        T value_or(T default_value) const noexcept(noexcept_copyable<T>())
        {
            if (mValue == nullptr)
            {
                return default_value;
            }

            return *mValue;
        }

        const T& value() const&
        {
            return *mValue;
        }

        T value() && noexcept(noexcept_movable<T>())
        {
            return std::move(*mValue);
        }

        T& value() &
        {
            return *mValue;
        }

        const T* operator->() const&
        {
            return mValue.get();
        }

        T* operator->() &
        {
            return mValue.get();
        }

        operator bool() const noexcept
        {
            return has_value();
        }
    };
} // namespace compliance

#endif // OPTIONAL_HPP
