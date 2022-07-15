#pragma once

#include "driver.hpp"

template< typename T, T MY_VALUE >
struct CONST_HOLDER {
	enum class VALUE_HOLDER : T {
		RET_VALUE = MY_VALUE,
	};
};

#define CONSTANT_HOLD( value ) ( ( decltype( value ) )CONST_HOLDER< decltype( value ), value >::VALUE_HOLDER::RET_VALUE )

// [!] build time hashing
#define __( s ) CONSTANT_HOLD( hash::fnv1a_ct( s ) )
// [!] run time hashing
#define ___( s ) hash::fnv1a_rt( s )

namespace hash
{
	namespace holder
	{
		constexpr static UINT32 seed  = 0x45C3370D;
		constexpr static UINT32 prime = 0x1000193;
	} // namespace holder

	inline UINT32 fnv1a_rt( const char* key, const UINT32 val = hash::holder::seed )
	{
		auto temp_hash = ( key[ 0 ] == '\0' ) ? val : fnv1a_rt( &key[ 1 ], ( val ^ UINT32( key[ 0 ] ) ) * hash::holder::prime );

		return temp_hash;
	}

	constexpr static UINT32 fnv1a_ct( char const* string, const UINT32 val = hash::holder::seed )
	{
		auto temp_hash = ( string[ 0 ] == '\0' ) ? val : fnv1a_ct( &string[ 1 ], ( val ^ UINT32( string[ 0 ] ) ) * hash::holder::prime );

		return temp_hash;
	}
} // namespace hash
