'''
Sensen Li

| Test for the set-constrained pseudorandom function (scPRF)

:Author:         Sensen Li
:Date:           11/2024
'''
from utils import setConstrainedPRF

def main():
    scPRF = setConstrainedPRF.SCPRF(65536)
    msk_SCPRF = scPRF.Setup(128)
    cons_set = [1,2,3,8,10,20,30,40,50,100]
    cons_key = scPRF.Cons(msk_SCPRF, cons_set)
    print(len(cons_key))
    print(cons_key)
    print('index = 0:   ' + str(scPRF.Eval(cons_key, 0)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 0, scPRF.tree.level, 0)))
    print('index = 1:   ' + str(scPRF.Eval(cons_key, 1)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 1, scPRF.tree.level, 0)))
    print('index = 2:   ' + str(scPRF.Eval(cons_key, 2)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 2, scPRF.tree.level, 0)))
    print('index = 3:   ' + str(scPRF.Eval(cons_key, 3)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 3, scPRF.tree.level, 0)))
    print('index = 5:   ' + str(scPRF.Eval(cons_key, 5)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 5, scPRF.tree.level, 0)))
    print('index = 8:   ' + str(scPRF.Eval(cons_key, 8)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 8, scPRF.tree.level, 0)))
    print('index = 10:   ' + str(scPRF.Eval(cons_key, 10)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 10, scPRF.tree.level, 0)))
    print('index = 50:   ' + str(scPRF.Eval(cons_key, 50)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 50, scPRF.tree.level, 0)))
    print('index = 80:   ' + str(scPRF.Eval(cons_key, 80)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 80, scPRF.tree.level, 0)))
    print('index = 100:   ' + str(scPRF.Eval(cons_key, 100)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 100, scPRF.tree.level, 0)))
    print('index = 65535:   ' + str(scPRF.Eval(cons_key, 65535)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 65535, scPRF.tree.level, 0)))
    
if __name__ == "__main__":
    debug = True
    main()