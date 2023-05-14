"""Provide functionality related to nftables for use with pyroute2.

TODO: Contribute back to pyroute2.

See: https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes

Rule generation tip
Step 1: Add rule using nft
Step 2: pyroute2.NFTables().get_rules() in order to obtain the high-level netlink VM representation
"""

import ipaddress
import struct

from pyroute2.nftables.main import NFTables as NFT

class DeferredExpression:
    def eval(self, nft, deferred_id, kwargs):
        """This class is a placeholder for an nftables expression. Inherit from this class to implement operations that
        are executed in the same transaction. If a rule contains an instance of this class instead of a regular
        expression, the eval method is called and the instance inside the rule is replaced with the result of the eval
        method.
        """
        return NotImplementedError()


class NFTables(NFT):
    def rule(self, cmd, **kwarg):
        self.begin()
        if 'expressions' in kwarg:
            expressions = []
            deferred_id = 0
            for exp_group in kwarg['expressions']:
                for exp in exp_group:
                    if isinstance(exp, DeferredExpression):
                        exp = exp.eval(self, deferred_id, kwarg)
                        deferred_id += 1
                    expressions.append(exp)
            kwarg['expressions'] = (expressions,)
        super(NFTables, self).rule(cmd, **kwarg)
        self.commit()


from pallium.nft.datatypes import *


class _Lookup:
    def __init__(self, name):
        self.name = name


class DeferredLookup(DeferredExpression):
    def __init__(self, func, newset_kwargs, newsetelem_kwargs):
        self._func = func
        self.newset_kwargs = newset_kwargs
        self.newsetelem_kwargs = newsetelem_kwargs

    def eval(self, nft, deferred_id, kwargs):
        self.newset_kwargs['table'] = self.newsetelem_kwargs['table'] = kwargs['table']
        self.newset_kwargs['id'] = self.newsetelem_kwargs['set_id'] = deferred_id
        nft.set('add', **self.newset_kwargs)
        nft.set_element('add', **self.newsetelem_kwargs)
        return self._func(deferred_id)


def dict2nla(d):
    return {'attrs': [(k, d[k] if not isinstance(d[k], dict) else dict2nla(d[k])) for k in d]}


def genex(name, kwarg):
    return dict2nla({
        'NFTA_EXPR_NAME': name,
        **({'NFTA_EXPR_DATA': {
            'NFTA_%s_%s' % (name.upper(), key.upper()): value for key, value in kwarg.items()
        }} if len(kwarg) > 0 else {})
    })


def gendata(value):
    return {'NFTA_DATA_VALUE': value}


def genverdict(verdict, chain=None):
    return {
        'NFTA_DATA_VERDICT': {
            'NFTA_VERDICT_CODE': verdict,
            **({'NFTA_VERDICT_CHAIN': chain} if chain is not None else {})
        }
    }


class ComparisonCommand:
    def __init__(self, op, data):
        self.op = op
        self.data = data


def _opposite_op(op):
    return {
        NFT_CMP_LT: NFT_CMP_GTE,
        NFT_CMP_LTE: NFT_CMP_GT,
        NFT_CMP_EQ: NFT_CMP_NEQ,
        NFT_CMP_NEQ: NFT_CMP_EQ,
        NFT_CMP_GT: NFT_CMP_LTE,
        NFT_CMP_GTE: NFT_CMP_LT
    }[op]


def _op_fn_from_code(code):
    return {
        NFT_CMP_LT: lt,
        NFT_CMP_LTE: lte,
        NFT_CMP_EQ: eq,
        NFT_CMP_NEQ: neq,
        NFT_CMP_GT: gt,
        NFT_CMP_GTE: gte
    }[code]


def lt(data):
    return [ComparisonCommand(NFT_CMP_LT, data)]


def lte(data):
    return [ComparisonCommand(NFT_CMP_LTE, data)]


def eq(data):
    return [ComparisonCommand(NFT_CMP_EQ, data)]


def neq(data):
    return [ComparisonCommand(NFT_CMP_NEQ, data)]


def gt(data):
    return [ComparisonCommand(NFT_CMP_GT, data)]


def gte(data):
    return [ComparisonCommand(NFT_CMP_GTE, data)]


class _Range:
    def __init__(self, lower, upper):
        self.lower = lower
        self.upper = upper


class _Set:
    def __init__(self):
        pass


def _normalize_lookup_set(set, transform, key_len):
    max_value = key_len * b'\xff'
    result = []
    for element in set:
        if _is_range(element):
            lower, upper = _get_range(element)
            assert lower <= upper
            result.append((transform(lower), transform(upper)))
        else:
            result.append((transform(element), transform(element)))
    result.sort(key=lambda x: x[0])
    collapsed = []
    if len(result) > 0:
        new_range = result[0]
        for i, next_range in enumerate(result):
            if i == 0:
                continue
            if new_range[1] >= next_range[0]:
                new_range = new_range[0], max(new_range[1], next_range[1])
            else:
                collapsed.append(new_range)
                new_range = next_range
        collapsed.append(new_range)

    exprs = []
    for (lower, upper) in collapsed:
        exprs.append(_gen_set_element(lower, False))
        if upper != max_value:
            plusone = (int.from_bytes(upper, "big", signed=False) + 1).to_bytes(key_len, "big", signed=False)
            exprs.append(_gen_set_element(plusone, True))
    return exprs


def _gen_deferred_lookup(func, newset_kwargs, newsetelem_kwargs, set, transform):
    if 'flags' not in newset_kwargs:
        newset_kwargs['flags'] = NFT_SET_ANONYMOUS | NFT_SET_CONSTANT
    if 'name' not in newset_kwargs:
        newset_kwargs['name'] = '__set%d'

    has_interval = False
    for element in set:
        if _is_range(element):
            has_interval = True

    if not has_interval:
        elements = [_gen_set_element(transform(element), False) for element in set]
    else:
        newset_kwargs['flags'] |= NFT_SET_INTERVAL
        elements = _normalize_lookup_set(set, transform, newset_kwargs['key_len'])
    newsetelem_kwargs['elements'] = elements
    newset_kwargs['desc'] = {'attrs': [('NFTA_SET_DESC_SIZE', len(newsetelem_kwargs['elements']))]}
    return DeferredLookup(func, newset_kwargs, newsetelem_kwargs)


def _is_range(obj):
    if isinstance(obj, str) or isinstance(obj, ipaddress.IPv4Address) or isinstance(obj, ipaddress.IPv6Address) \
            or isinstance(obj, ipaddress.IPv4Network) or isinstance(obj, ipaddress.IPv6Network):
        try:
            return ipaddress.ip_network(obj, False).num_addresses > 1
        except ValueError:
            pass
    return isinstance(obj, tuple) and len(obj) == 2 or isinstance(obj, _Range)


def _get_range(r):
    if not _is_range(r):
        return None
    if isinstance(r, tuple) and len(r) == 2:
        return r[0], r[1]
    elif isinstance(r, _Range):
        return r.lower, r.upper
    try:
        network = ipaddress.ip_network(r, False)
        return network.network_address, network.broadcast_address
    except ValueError:
        pass


def _is_set(obj):
    return isinstance(obj, set) or isinstance(obj, frozenset)


def _is_command_list(obj):
    return isinstance(obj, list) and len(obj) > 0 and isinstance(obj[0], ComparisonCommand)


def _get_first_inner(obj):
    if _is_command_list(obj):
        obj = obj[0].data
    if _is_range(obj):  # Object is a range
        return _get_range(obj)[0]
    if _is_set(obj):
        if len(obj) == 0:
            return None
        first = next(iter(obj))
        if _is_range(first):
            return _get_range(first)[0]
        else:
            return first
    else:
        return obj


def masquerade():
    return [genex('masq', {})]


def _gen_set_element(value, interval_end=False):
    return dict2nla({
        'NFTA_SET_ELEM_KEY': gendata(value),
        **({'NFTA_SET_ELEM_FLAGS': NFT_SET_ELEM_INTERVAL_END} if interval_end else {})
    })


def _lookup_set(set, sreg, flags=0):
    d = {
        'sreg': sreg,
        'flags': flags
    }
    if isinstance(set, int):
        d['set_id'] = set
        d['set'] = '__set%d'
    else:
        d['set'] = set
    return genex('lookup', d)


class ExpressionWrapper(list):
    def __init__(self, *args, **kwargs):
        super(ExpressionWrapper, self).__init__(*args, **kwargs)
        self._matcher = None


class LoadExpression:
    def __init__(self, inner, requirements, prelude=None, loaded=False):
        if prelude is None:
            prelude = []
        self.prelude = prelude
        self.inner = inner
        self.requirements = requirements
        self.loaded = loaded

    def load(self, *args, **kwargs):
        result = self._prelude()
        if not self.loaded:
            result += self.inner.load(*args, **kwargs)
        return result

    def _prelude(self):
        if self.loaded:
            return self.requirements + self.prelude
        return self.requirements + self.prelude + self.inner.load()

    def _cmp(self, other, op):
        return self._prelude() + self.inner.gen_operand_cmp(other, op)

    def _eq(self, other, op):
        if self.inner.supports_ranges and self.inner.is_range(other):
            return self._prelude() + self.inner.gen_operand_range(other, op)
        elif self.inner.is_set(other):
            return self._prelude() + self.inner.gen_operand_set(other, op)
        return self._cmp(other, op)

    def __lt__(self, other):
        return self._cmp(other, NFT_CMP_LT)

    def __le__(self, other):
        return self._cmp(other, NFT_CMP_LTE)

    def __eq__(self, other):
        return self._eq(other, NFT_CMP_EQ)

    def __ne__(self, other):
        return self._eq(other, NFT_CMP_NEQ)

    def __ge__(self, other):
        return self._cmp(other, NFT_CMP_GTE)

    def __gt__(self, other):
        return self._cmp(other, NFT_CMP_GT)

    def _bitwise(self, exp):
        prelude = ([] if self.loaded else self.inner.load()) + self.prelude + exp
        return LoadExpression(self.inner, self.requirements, prelude, loaded=True)

    def _bitwise_bool(self, mask=None, xor=None):
        return self._bitwise(self.inner.gen_operand_bitwise_bool(mask=mask, xor=xor))

    def _bitwise_shift(self, op, shift):
        return self._bitwise(self.inner.gen_operand_bitwise_shift(op, shift))

    def __and__(self, other):
        return self._bitwise_bool(mask=other)

    def __xor__(self, other):
        return self._bitwise_bool(xor=other)

    def __or__(self, other):
        return self._bitwise(self.inner.gen_operand_or(other))

    def __rshift__(self, other):
        return self._bitwise_shift(NFT_BITWISE_RSHIFT, other)

    def __lshift__(self, other):
        return self._bitwise_shift(NFT_BITWISE_LSHIFT, other)


class Matcher:
    type = None
    extractor = None
    key = None
    supports_ranges = False
    supports_set = False

    def pack(self, value):
        raise NotImplementedError()

    def extract(self, dreg=NFT_REG_1):
        return self.extractor.extract(self.key, dreg=dreg)

    def load(self, dreg=NFT_REG_1):
        return self.extract(dreg=dreg)

    def match(self, value, reg=NFT_REG_1):
        return self.load(reg) + self.gen_operand(value, reg)

    def is_range(self, value):
        return self.get_range(value) is not None

    def is_set(self, value):
        return isinstance(value, frozenset) or isinstance(value, set)

    def get_range(self, value):
        if isinstance(value, tuple) and len(value) == 2:
            return value[0], value[1]
        elif isinstance(value, _Range):
            return value.lower, value.upper
        return None

    def gen_operand_bitwise_shift(self, op, shift, reg=NFT_REG_1):
        if not isinstance(shift, int):
            raise TypeError('Shift operand must be integer.')
        byte_length = (self.type.size + 7) // 8
        return [genex('bitwise', {
            'sreg': reg,
            'dreg': reg,
            'len': byte_length,
            'op': op,
            'data': gendata(struct.pack('=I', shift))
        })]

    def gen_operand_or(self, value, reg=NFT_REG_1):
        xor = self.pack(value)
        # Invert all bits from xor value:
        mask = bytes([~b & 0xff for b in xor])
        return [genex('bitwise', {
            'sreg': reg,
            'dreg': reg,
            'len': len(xor),
            'op': NFT_BITWISE_BOOL,
            'mask': gendata(mask),
            'xor': gendata(xor)
        })]

    def gen_operand_bitwise_bool(self, mask=None, xor=None, reg=NFT_REG_1):
        byte_length = (self.type.size + 7) // 8
        packed_mask = self.pack(mask) if mask is not None else byte_length * b'\xff'
        packed_xor = self.pack(xor) if xor is not None else byte_length * b'\x00'
        return [genex('bitwise', {
            'sreg': reg,
            'dreg': reg,
            'len': byte_length,
            'op': NFT_BITWISE_BOOL,
            'mask': gendata(packed_mask),
            'xor': gendata(packed_xor)
        })]

    def gen_operand_range(self, data, operator, reg=NFT_REG_1):
        if operator not in {NFT_CMP_EQ, NFT_CMP_NEQ}:
            raise Exception('Unsupported operator for range.')
        range = self.get_range(data)
        if range is None:
            raise Exception('Invalid range.')
        if range[0] != range[1]:
            lower, upper = range
            return [genex('range', {
                'sreg': reg,
                'op': {NFT_CMP_EQ: NFT_RANGE_EQ, NFT_CMP_NEQ: NFT_RANGE_NEQ}[operator],
                'from_data': self.gen_data(lower),
                'to_data': self.gen_data(upper)
            })]
        else:  # No need for a range
            return self.gen_operand_cmp(range[0], operator, reg=NFT_REG_1)

    def gen_data(self, value):
        return gendata(self.pack(value))

    def gen_operand_cmp(self, data, operator, reg=NFT_REG_1):
        return [genex('cmp', {
                    'sreg': reg,
                    'op': operator,
                    'data': gendata(self.pack(data))
                })]

    def gen_operand_list(self, commands, reg, op):
        raise NotImplementedError()

    def gen_operand_set(self, data, operator, reg=NFT_REG_1):
        if operator not in {NFT_CMP_EQ, NFT_CMP_NEQ}:
            raise Exception('Unsupported operator for set.')
        lookup_flags = NFT_LOOKUP_F_INV if operator == NFT_CMP_NEQ else 0
        first = _get_first_inner(data)
        key_len = 0 if first is None else len(self.pack(first))
        return [_gen_deferred_lookup(
            lambda set_id: _lookup_set(set_id, reg, lookup_flags),
            {
                'key_type': self.type.type,
                'key_len': key_len,
            }, {}, data, self.pack
        )]

    def gen_operand(self, commands, reg):
        result = []
        if isinstance(commands, _Lookup):
            return [_lookup_set(commands.name, reg)]
        elif not isinstance(commands, list) or isinstance(commands, LoadExpression):
            commands = eq(commands)
        elif isinstance(commands, list) and (len(commands) == 0 or not isinstance(commands[0], ComparisonCommand)):
            return self.gen_operand_list(commands, reg, NFT_CMP_EQ)
        for cmd in commands:
            if self.supports_ranges and self.is_range(cmd.data):
                result.extend(self.gen_operand_range(cmd.data, cmd.op))
            elif _is_set(cmd.data):
                result.extend(self.gen_operand_set(cmd.data, cmd.op))
            elif isinstance(cmd.data, LoadExpression):
                raise TypeError('Expression loading not supported in this context')
            elif isinstance(cmd.data, list):
                return self.gen_operand_list(cmd.data, reg, cmd.op)
            else:
                result.extend(self.gen_operand_cmp(cmd.data, cmd.op))
        return result

    def immediate(self, value, reg=NFT_REG_1):
        return [genex('immediate', {
            'dreg': reg,
            'data': gendata(self.pack(value))
        })]

    def __call__(self, value=None, *, set=None):
        if set is not None:
            if not self.supports_set:
                raise TypeError('Setting is unsupported for this field.')
            if isinstance(set, LoadExpression):
                return set.load() + self.extractor.store(self.key)
            return self.immediate(set) + self.extractor.store(self.key)
        return self.match(value)


class IntMatcher(Matcher):
    type = IntegerType
    supports_ranges = True

    def __init__(self, key, type, shift=0, set=False):
        self.key = key
        self.type = type
        self.shift = shift
        self.supports_set = set

    def pack(self, value):
        fmt = self.type.byteorder if self.type.byteorder is not None else ''
        if self.type.size <= 8:
            fmt += 'B'
        elif self.type.size <= 16:
            fmt += 'H'
        elif self.type.size <= 32:
            fmt += 'I'
        else:
            fmt += 'Q'
        return struct.pack(fmt, value << self.shift)

    def gen_operand_list(self, commands, reg, op):
        bits = 0
        for value in commands:
            bits |= value
        length = self.type.size // 8
        op = _op_fn_from_code(_opposite_op(op))
        return [genex('bitwise', {
            'sreg': reg,
            'dreg': reg,
            'len': length,
            'op': NFT_BITWISE_BOOL,
            'mask': gendata(self.pack(bits)),
            'xor': gendata(length * b'\x00')
        })] + self.gen_operand(op(bits), reg)


class ProtocolIpAddressMatcher(IntMatcher):
    ip_addr_class = ipaddress.IPv4Address
    ip_network_class = ipaddress.IPv4Network

    def pack(self, value):
        return self.ip_addr_class(value).packed
    
    def gen_operand_range(self, data, operator, reg=NFT_REG_1):
        range = self.get_range(data)
        summarized = [r for r in ipaddress.summarize_address_range(*range)]
        if len(summarized) == 1 and summarized[0].network_address != summarized[0].broadcast_address:
            prefixlen = summarized[0].prefixlen
            address_len = len(summarized[0].network_address.packed)
            mask = '1' * prefixlen + (address_len * 8 - prefixlen) * '0'
            mask = int(mask, 2).to_bytes(address_len, byteorder='big')
            return [genex('bitwise', {
                'sreg': reg,
                'dreg': reg,
                'xor': gendata(b'\x00' * address_len),
                'mask': gendata(mask),
                'len': address_len
            })] + self.gen_operand_cmp(summarized[0].network_address, operator)
        return super(ProtocolIpAddressMatcher, self).gen_operand_range(data, operator, reg=reg)

    def get_range(self, value):
        if isinstance(value, (str, self.ip_network_class)):
            try:
                network = self.ip_network_class(value, False)
                return network.network_address, network.broadcast_address
            except ValueError:
                pass
        return super(ProtocolIpAddressMatcher, self).get_range(value)


class ProtocolIp6AddressMatcher(ProtocolIpAddressMatcher):
    ip_addr_class = ipaddress.IPv6Address
    ip_network_class = ipaddress.IPv6Network


class StringMatcher(Matcher):
    supports_ranges = False

    def gen_operand_list(self, commands, reg, op):
        raise TypeError('String types ')

    def __init__(self, key, type, size=None):
        self.key = key
        self.size = type.size if type.size is not None else size
        self.type = type

    def pack(self, value):
        if isinstance(value, str):
            value = value.encode()
        return struct.pack(str(self.size // 8) + 's', value)


def get_matcher(tp):
    if isinstance(tp, StringType) or issubclass(tp, StringType):
        return StringMatcher
    if tp == IpAddrType:
        return ProtocolIpAddressMatcher
    elif tp == Ip6AddrType:
        return ProtocolIp6AddressMatcher
    return IntMatcher


class Extractor:
    base = None
    fields = {}
    requirements = []

    def __init__(self):
        for field_name in self.fields.copy():
            field = self.fields[field_name]
            if isinstance(field, tuple):
                field = self.fields[field_name] = get_matcher(field[1])(field[0], field[1])
            field.name = field_name
            field.extractor = self

    def extract(self, key, dreg):
        raise NotImplementedError()

    def __call__(self, **kwargs):
        expressions = self.requirements.copy()

        for field_name in kwargs:
            if field_name not in self.fields:
                raise TypeError('The field "%s" was not found.' % field_name)
            field = self.fields[field_name]
            expressions.extend(field.match(kwargs[field_name]))
        return expressions

    def _load_or_set(self, field_name):
        field = self.fields[field_name]
        parent = self

        class CallOrFlags:
            def __call__(self, *args, **kwargs):
                if 'dreg' in kwargs and len(kwargs) == 1 or len(args) == 0 and 'set' not in kwargs:
                    return LoadExpression(field, parent.requirements)
                return parent.requirements + field(*args, **kwargs)

            def __getattr__(self, item):
                if item not in field.type.symbols:
                    raise AttributeError('The flag "%s" was not found.' % item)
                return field.type.symbols[item]

        return CallOrFlags()

    def __getattr__(self, item):
        if item not in self.fields:
            raise AttributeError('The field "%s" was not found.' % item)
        # return self.fields[item]
        return self._load_or_set(item)


class Meta(Extractor):
    def extract(self, key, dreg=NFT_REG_1):
        return [genex('meta', {
            'key': key,
            'dreg': dreg
        })]

    def store(self, key, sreg=NFT_REG_1):
        return [genex('meta', {
            'key': key,
            'sreg': sreg
        })]

    fields = {
        'length': IntMatcher(NFT_META_LEN, U32HEType),
        'protocol': IntMatcher(NFT_META_PROTOCOL, NfprotoType),
        'nfproto': IntMatcher(NFT_META_NFPROTO, U8Type),
        'l4proto': IntMatcher(NFT_META_L4PROTO, U8Type),
        'priority': IntMatcher(NFT_META_PRIORITY, TchandleType, set=True),
        'mark': IntMatcher(NFT_META_MARK, MarkType, set=True),
        'iifname': StringMatcher(NFT_META_IIFNAME, IfnameType),
        'oifname': StringMatcher(NFT_META_OIFNAME, IfnameType),
        'iif': IntMatcher(NFT_META_IIF, IfindexType),
        'oif': IntMatcher(NFT_META_OIF, IfindexType),
        'iiftype': IntMatcher(NFT_META_IIFTYPE, ArphdrType),
        'oiftype': IntMatcher(NFT_META_OIFTYPE, ArphdrType),
        'skuid': IntMatcher(NFT_META_SKUID, UidType),
        'skgid': IntMatcher(NFT_META_SKGID, GidType),
        'nftrace': IntMatcher(NFT_META_NFTRACE, U8Type, set=True),
        'rtclassid': IntMatcher(NFT_META_RTCLASSID, RealmType),
        'bri_iifname': StringMatcher(NFT_META_BRI_IIFNAME, IfnameType),
        'bri_oifname': StringMatcher(NFT_META_BRI_OIFNAME, IfnameType),
        'pkttype': IntMatcher(NFT_META_PKTTYPE, PkttypeType, set=True),
        'cpu': IntMatcher(NFT_META_CPU, U32HEType),
        'iifgroup': IntMatcher(NFT_META_IIFGROUP, DevgroupType),
        'oifgroup': IntMatcher(NFT_META_OIFGROUP, DevgroupType),
        'prandom': IntMatcher(NFT_META_PRANDOM, U32BEType),
        'secpath': IntMatcher(NFT_META_SECPATH, BooleanType),
        'iifkind': IntMatcher(NFT_META_IIFKIND, IfnameType),
        'oifkind': IntMatcher(NFT_META_OIFKIND, IfnameType),
        'ibrpvid': IntMatcher(NFT_META_BRI_IIFPVID, U16HEType),
        'time': IntMatcher(NFT_META_TIME_NS, DateType),
        'day': IntMatcher(NFT_META_TIME_DAY, DayType),
        'hour': IntMatcher(NFT_META_TIME_HOUR, HourType),
        'secmark': IntMatcher(NFT_META_SECMARK, U32HEType, set=True),
        'sdif': IntMatcher(NFT_META_SDIF, IfindexType),
        'sdifname': StringMatcher(NFT_META_SDIFNAME, IfnameType)
    }


meta = Meta()

# When using nftables, these keys do not require a meta prefix
# See meta_key_is_unqualified in nftables/src/meta.c
iif = meta.iif
oif = meta.oif
iifname = meta.iifname
oifname = meta.oifname
iifgroup = meta.iifgroup
oifgroup = meta.oifgroup


class Protocol(Extractor):
    checksum = NFT_PAYLOAD_CSUM_NONE
    checksum_key = None
    checksum_type = None

    def __init__(self):
        super().__init__()
        for field in self.fields:
            self.fields[field].supports_set = True
            self.fields[field].shift = (8 - self.fields[field].key[0] + self.fields[field].key[1]) % 8

    def extract(self, key, dreg=NFT_REG_1):
        start, length = key
        start_byte = start // 8
        end_byte = (start + length - 1) // 8
        byte_length = end_byte - start_byte + 1
        result = [
            genex('payload', {
                'dreg': dreg,
                'base': self.base,
                'offset': start_byte,
                'len': byte_length
            })
        ]
        if start % 8 != 0 or length % 8 != 0:
            mask = b'\xff' * byte_length
            trailing_zeroes = (start + length) % 8
            mask = bytes([mask[0] >> start % 8]) + mask[1:]
            mask = mask[:-1] + bytes([(mask[-1] >> trailing_zeroes) << trailing_zeroes])

            result.append(genex('bitwise', {
                'sreg': dreg,
                'dreg': dreg,
                'len': byte_length,
                'op': NFT_BITWISE_BOOL,
                'mask': gendata(mask),
                'xor': gendata(byte_length * b'\x00')
            }))
        return result

    def store(self, key, sreg=NFT_REG_1):
        start, length = key
        start_byte = start // 8
        end_byte = (start + length - 1) // 8
        byte_length = end_byte - start_byte + 1
        return [genex('payload', {
            'sreg': sreg,
            'base': self.base,
            'offset': start_byte,
            'len': byte_length,

            # Recompute the protocol checksum if applicable:
            **({
                'csum_type': self.checksum_type,
                'csum_offset': self.fields[self.checksum_key].key[0] // 8
               } if self.checksum_type is not None else {})
        })]


class UDP(Protocol):
    base = NFT_PAYLOAD_TRANSPORT_HEADER
    requirements = meta(l4proto=17)
    checksum_key = 'checksum'
    checksum_type = NFT_PAYLOAD_CSUM_INET
    fields = {
        'sport': ((0, 16), InetServiceType),
        'dport': ((16, 16), InetServiceType),
        'length': ((32, 16), U16BEType),
        'checksum': ((48, 16), U16BEType)
    }


udp = UDP()


class TCP(Protocol):
    base = NFT_PAYLOAD_TRANSPORT_HEADER
    requirements = meta(l4proto=6)
    checksum_key = 'checksum'
    checksum_type = NFT_PAYLOAD_CSUM_INET
    fields = {
        'sport': ((0, 16), InetServiceType),
        'dport': ((16, 16), InetServiceType),
        'sequence': ((32, 32), U32BEType),
        'ackseq': ((64, 32), U32BEType),
        'doff': ((96, 4), U8Type),
        'reserved': ((100, 4), U8Type),
        'flags': ((104, 8), TcpFlagType),
        'window': ((112, 16), U16BEType),
        'checksum': ((128, 16), U16BEType),
        'urgptr': ((144, 16), U16BEType),
    }


tcp = TCP()


class IP(Protocol):
    base = NFT_PAYLOAD_NETWORK_HEADER
    requirements = meta(nfproto=NFPROTO_IPV4)
    checksum_key = 'checksum'
    checksum_type = NFT_PAYLOAD_CSUM_INET
    fields = {
        'version': ((0, 4), IntegerType),
        'hdrlength': ((4, 4), IntegerType),
        'dscp': ((8, 6), DscpType),
        'ecn': ((14, 2), EcnType),
        'length': ((16, 16), IntegerType),
        'id': ((32, 16), IntegerType),
        'frag_off': ((48, 16), IntegerType),
        'ttl': ((64, 8), IntegerType),
        'protocol': ((72, 8), IntegerType),
        'checksum': ((80, 16), IntegerType),
        'saddr': ((96, 32), IpAddrType),
        'daddr': ((128, 32), IpAddrType),
    }


ip4 = IP()


class IP6(Protocol):
    base = NFT_PAYLOAD_NETWORK_HEADER
    requirements = meta(nfproto=NFPROTO_IPV6)
    fields = {
        'version': ((0, 4), IntegerType),
        'dscp': ((4, 6), DscpType),
        'ecn': ((10, 2), EcnType),
        'flowlabel': ((12, 20), IntegerType),
        'length': ((32, 16), IntegerType),
        'nexthdr': ((48, 8), IntegerType),
        'hoplimit': ((56, 8), IntegerType),
        'saddr': ((64, 128), Ip6AddrType),
        'daddr': ((192, 128), Ip6AddrType)
    }


ip6 = IP6()


class CT(Extractor):  # nftables/src/ct.c
    def extract(self, key, dreg=NFT_REG_1):
        return [genex('ct', {
            'dreg': NFT_REG_1,
            'key': key
        })]

    fields = {
        'state': IntMatcher(NFT_CT_STATE, CtStateType),
        'direction': IntMatcher(NFT_CT_DIRECTION, CtDirType),
        'mark': IntMatcher(NFT_CT_MARK, MarkType, set=True),
        'expiration': IntMatcher(NFT_CT_EXPIRATION, TimeType),
        'helper': StringMatcher(NFT_CT_HELPER, StringType, NFT_HELPER_NAME_LEN),
        'l3proto': IntMatcher(NFT_CT_L3PROTOCOL, NfprotoType),
        # TODO: Add all
    }


ct = CT()


# noinspection PyShadowingBuiltins
def counter(*, packets=0, bytes=0):
    return [genex('counter', {'bytes': bytes, 'packets': packets})]


def family_from_version(version):
    if version == 4:
        return NFPROTO_IPV4
    elif version == 6:
        return NFPROTO_IPV6


def dnat(*, to):
    ip_address = ipaddress.ip_address(to[0])
    return [
        genex('immediate', {
            'dreg': NFT_REG_1,
            'data': gendata(ip_address.packed)
        }),
        genex('immediate', {
            'dreg': NFT_REG_2,
            'data': gendata(struct.pack('!H', to[1]))
        }),
        genex('nat', {
            'type': NFT_NAT_DNAT,
            'family': family_from_version(ip_address.version),
            'reg_addr_min': NFT_REG_1,
            'reg_addr_max': NFT_REG_1,
            'reg_proto_min': NFT_REG_2,
            'reg_proto_max': NFT_REG_2,
            'nat_flags': NF_NAT_RANGE_PROTO_SPECIFIED
        })]


def snat(*, to):
    network = ipaddress.ip_network(to, False)
    reg2 = NFT_REG_1
    result = []
    if network.num_addresses > 1:
        reg2 = NFT_REG_2
        result += [genex('immediate', {
            'dreg': reg2,
            'data': gendata(network.broadcast_address.packed)
        })]
    result += [
        genex('immediate', {
            'dreg': NFT_REG_1,
            'data': gendata(network.network_address.packed)
        }),
        genex('nat', {
            'type': NFT_NAT_SNAT,
            'family': family_from_version(network.version),
            'reg_addr_min': NFT_REG_1,
            'reg_addr_max': reg2,
            'nat_flags': NF_NAT_RANGE_MAP_IPS
        })]
    return result


def _ip_version_from_param(param):
    if param is None:
        return None
    return ipaddress.ip_network(_get_first_inner(param)).version


def _assign_consistent(old_value, new_value):
    if new_value is None:
        return old_value
    if old_value is not None and old_value != new_value:
        raise ValueError('Mixture of IPv4 and IPv6 specific features unsupported')
    return new_value


class DualStackIp:
    # TODO: Implement __getattr__, so that e.g. ip.saddr('1.1.1.1') can be used

    def __call__(self, **kwargs):
        version = kwargs.get('version', None)
        saddr = kwargs.get('saddr', None)
        daddr = kwargs.get('daddr', None)
        version = _assign_consistent(version, _ip_version_from_param(saddr))
        version = _assign_consistent(version, _ip_version_from_param(daddr))

        for argname in kwargs:
            if hasattr(ip4, argname) and not hasattr(ip6, argname):
                version = _assign_consistent(version, 4)
            if hasattr(ip6, argname) and not hasattr(ip4, argname):
                version = _assign_consistent(version, 6)
        if version is None:
            raise ValueError('Failed to determine IP version.')

        return {
            4: ip4,
            6: ip6,
        }[version](**kwargs)


ip = DualStackIp()


def _verdict(v, chain=None):
    return [genex('immediate', {
        'dreg': NFT_REG_VERDICT,
        'data': genverdict(v, chain)
    })]


def drop():
    return _verdict(NF_DROP)


def accept():
    return _verdict(NF_ACCEPT)


def ret():
    return _verdict(NFT_RETURN)


def jump(chain):
    return _verdict(NFT_JUMP, chain)


def goto(chain):
    return _verdict(NFT_GOTO, chain)


def at(name):
    return _Lookup(name)
