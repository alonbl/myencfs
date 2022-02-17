EAPI=7

DESCRIPTION="myencfs example application"
HOMEPAGE="https://github.com/alonbl/myencfs"

if [[ ${PV} = 9999 ]]; then
	EGIT_REPO_URI="https://github.com/alonbl/myencfs"
	inherit git-r3 autotools
else
	SRC_URI="https://github.com/alonbl/${PN}/releases/download/${P}/${P}.tar.bz2"
	KEYWORDS="~alpha ~amd64 ~arm ~arm64 ~hppa ~ia64 ~m68k ~mips ~ppc ~ppc64 ~riscv ~s390 ~sparc ~x86"
fi

LICENSE="BSD"
SLOT="0"
IUSE_MYENCFS_CRYPTO="myencfs_crypto_openssl myencfs_crypto_mbedtls"
IUSE="+bio-file +encrypt +decrypt +tools fuse static-libs test ${IUSE_MYENCFS_CRYPTO}"

REQUIRED_USE="
	^^ ( ${IUSE_MYENCFS_CRYPTO} )
	tools? ( bio-file )
	fuse? ( bio-file decrypt )
"

RDEPEND="
	myencfs_crypto_openssl? ( >=dev-libs/openssl-1.1:=[static-libs(+)?] )
	myencfs_crypto_mbedtls? ( >=net-libs/mbedtls-3.1:=[static-libs(+)?] )
	fuse? ( sys-fs/fuse:3= )
"
DEPEND="${RDEPEND}"
BDEPEND="virtual/pkgconfig"

DOCS=( README.md )

src_prepare() {
	default
	[[ ${PV} = 9999 ]] && eautoreconf
}

src_configure() {
	local crypto
	use myencfs_crypto_openssl && crypto="openssl"
	use myencfs_crypto_mbedtls && crypto="mbedtls"

	econf \
		$(use_enable bio-file) \
		$(use_enable encrypt) \
		$(use_enable decrypt) \
		$(use_enable test tests) \
		$(use_enable tools tool) \
		$(use_enable fuse) \
		$(use_enable static-libs static) \
		--with-crypto="${crypto}" \
		--with-build-id="${PF}"
}

src_install() {
	default
	find "${D}" -name '*.la' -delete || die
}
