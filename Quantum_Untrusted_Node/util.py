# =============================================================================
# util.py
# =============================================================================
# © Qubitrix™ Quantum Systems
# Proprietary Source Code – For internal use only
# Unauthorized copying, distribution, or reverse engineering is prohibited.
# =============================================================================
# Changelog
# -----------------------------------------------------------------------------
# v1.0.0 - Initial Release
#   - Added utilities for data transmission and entropy validation.
# -----------------------------------------------------------------------------

from collections import Counter

from scipy.stats import binomtest

def xor(a: bytes, b: bytes):
    # zip会以长度短的为准
    return bytes([ x ^ y for x, y in zip(a, b) ])

def validate_entropy(bits: str):
    # 从密钥长度至少为64位
    if len(bits) < 64:
        return False
    # 统计0和1出现的次数
    counts = Counter(bits)
    # 只检查了出现的次数随机性，没有检查出现的顺序的随机性
    binomial_test = binomtest(
        counts.get('0', 0), # 0的次数
        n = len(bits), # 总长度
        p = 0.5, 
        alternative = 'two-sided'# 双侧检验
    )

    if binomial_test.pvalue < 0.01:
        return False

    return True