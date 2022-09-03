#!/usr/bin/env python3

import pdb
import click
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib2tikz import save as tikz_save
import math
import os
import sys
import subprocess

outliers = 20

# From https://stackoverflow.com/questions/22987015/slice-pandas-dataframe-by-multiindex-level-or-sublevel
def filter_by(df, constraints):
    """Filter MultiIndex by sublevels."""
    indexer = [constraints[name] if name in constraints else slice(None)
               for name in df.index.names]
    return df.loc[tuple(indexer)] if len(df.shape) == 1 else df.loc[tuple(indexer),]

pd.Series.filter_by = filter_by
pd.DataFrame.filter_by = filter_by


def load_csv(cpufreq, fname, typ):
    df = pd.read_csv(fname, sep=',')
    label = ['TIME', typ]
    if len(df.columns) == 3:
        label += ['MAX']
    df.columns = label
    df['TIME'] = df['TIME'] / (cpufreq)
    return df

def load_ecall(cpufreq, fname):
    return load_csv(cpufreq, fname, 'ECALLS')

def load_ocall(cpufreq, fname):
    return load_csv(cpufreq, fname, 'OCALLS')

def compute_overhead(vmean, vvar, smean, svar):
    (overhead, overheadvar) = compute_ratio(vmean, vvar, smean, svar)
    overhead = (overhead - 1) * 100
    overheadvar = overheadvar * 100 * 100
    return (overhead, overheadvar)

def compute_ratio(vmean, vvar, smean, svar):
    overhead = (smean / vmean)
    # Computing variance:
    # 1. Var(X+a) = Var(x) for a const.
    # 2. Var(X*b) = Var(x) * b² for b const.
    # 3. Variance of ratios
    #    var(S/V) approx. (µS/µV)^2 * [ varS/µS² + varV/µV² -2 Cov(R,V)/(µS*µV)]
    #    Cov(S,V) = 0 if independent
    #    See: www.stat.cmu.edu/~hseltman/files/ratio.pdf
    # Overall:
    # Var(overhead) = var(s/v) * 100²
    overheadvar = pow((smean / vmean),2) * ( (svar / pow(smean,2)) + (vvar / pow(vmean,2)) )
    return (overhead, overheadvar)

def eval_ecall(matrix):
    median = matrix['TIME'].median()
    lenold = len(matrix)
    matrix = matrix[matrix['TIME'] < outliers * median]
    print("Dropped {} entries\n".format(lenold - len(matrix)))
    mean = matrix['TIME'].mean()
    var = matrix['TIME'].var()
    assert matrix['ECALLS'].max() == matrix['ECALLS'].min()
    ecalls = matrix['ECALLS'].max()
    return (ecalls, mean, var)

def eval_ocall(matrix, emean, evar):
    # Group by same number of ocalls
    group = matrix.groupby(['OCALLS'])['TIME']

    # Adjust mean by removing ecall latency
    mean  = group.mean() - emean
    # Variances add up (assuming ecall/ocall measurements are independent)
    var   = group.var() + evar

    return (mean, var)

def medianfilter(df):
    median = df['TIME'].median()
    
    return df[(df['TIME'] < outliers * median) & (df['TIME'] > median / outliers) ]

def eval_pfs(matrix, emean, evar):
    # Filter outliers
    group = matrix.groupby(['OWRITE', 'PAYLOAD'])
    lenold = len(matrix)
    newmatrix = group.apply(medianfilter)
    newmatrix = newmatrix.reset_index(drop=True)
    matrix = newmatrix
    print("Dropped {} PFS entries out of {}\n".format(lenold - len(matrix), lenold))

    # Group by same number of chunks (OWRITE) and payload
    group = matrix.groupby(['OWRITE', 'PAYLOAD'])['TIME']
    # Adjust mean by removing ecall latency
    mean  = group.mean() - emean
    # Variances add up (assuming independence)
    var   = group.var() + evar
    return (mean, var)

def print_time(title, mean, var):
    stddef = math.sqrt(var)
    print("%10s: %.2f (+%.3f)" % (title, mean, stddef))

#~ def correct_idx(matrix, worktime):
    #~ newidx = matrix.index / worktime


def load_pfs_csv(cpufreq, fname):
    df = pd.read_csv(fname, sep=',')
    df.columns = ['TIME', 'OWRITE', 'PAYLOAD']
    df['TIME'] = df['TIME'] / (cpufreq)
    return df

def plot_pfs_payload(pfsmean, pfsvar, pfsstd, payload):
    mean = pfsmean.filter_by({'PAYLOAD':[payload]})
    var = pfsvar.filter_by({'PAYLOAD':[payload]})
    std = pfsstd.filter_by({'PAYLOAD':[payload]})
    idx = mean.index.get_level_values('OWRITE')
    plt.plot(idx, mean)
    plt.fill_between(idx, (mean - 2 * std).squeeze(), (mean + 2 * std).squeeze(), alpha=0.2)

def plot_pfs_chunks(ax1, pfsmean, pfsvar, pfsstd, chunks, fmt, color):
    mean = pfsmean.filter_by({'OWRITE':[chunks]})
    var = pfsvar.filter_by({'OWRITE':[chunks]})
    std = pfsstd.filter_by({'OWRITE':[chunks]})
    idx = mean.index.get_level_values('PAYLOAD')
    ax1.plot(idx, mean, color + fmt)
    ax1.fill_between(idx, (mean - 2 * std).squeeze(), (mean + 2 * std).squeeze(), alpha=0.2, color=color)

def export_tikz(filename, **kwargs):
    ret = tikz_save(filename, **kwargs)
    # Manual bugfix of https://github.com/nschloe/matplotlib2tikz/issues/202
    #
    # Comment out \addlegendimage in resulting .tex file
    # sed -i -E "s/(\\\addlegendimage)/%\\1/g" <filename>
    result = subprocess.run(["sed", "-i", "-E", "s/([\\]addlegendimage)/%\\1/g", filename])
    assert result.returncode == 0
    return ret

@click.command()
@click.argument('eocalls', type=int)
@click.option('--ocalls', type=int, default=0)
@click.option('--pfsvanilla', type=str, default=None)
@click.option('--pfssbox', type=str, default=None)
@click.option('--show', type=bool, default=False)
@click.option('--freq', type=bool, default=False)
def main(eocalls, ocalls, pfsvanilla, pfssbox, show, freq):
    global somean, vomean, overhead, overheadvar, overheadstd
    global vpfs, spfs, vpfsmean, vpfsvar, vpfsstd, spfsmean, spfsvar, spfsstd
    cpufreq = 1
    if freq:
        with open('cpufreq.txt') as f:
            cpufreq = int(f.read()) * 1000

    # Evaluate ECALL benchmarks in CPU cycles
    ve = load_ecall(1, 'vanilla_ecalls_{}.csv'.format(eocalls))
    vecalls, vemean, vevar = eval_ecall(ve)
    print_time("Vanilla E", vemean, vevar)

    se = load_ecall(1, 'sbox_ecalls_{}.csv'.format(eocalls))
    secalls, semean, sevar = eval_ecall(se)
    print_time("SGXJail E", semean, sevar)

    # Evaluate OCALLSingle benchmarks in CPU cycles
    vos = load_ecall(1, 'vanilla_ocallsSingle_{}.csv'.format(eocalls))
    voscalls, vosmean, vosvar = eval_ecall(vos)
    plt.boxplot(vos['TIME'])

    # Adjust ocall mean by removing ecall latency and adding variances
    vosmean = vosmean - vemean
    vosvar  = vosvar + vevar
    print_time("Vanilla O", vosmean, vosvar)

    sos = load_ecall(1, 'sbox_ocallsSingle_{}.csv'.format(eocalls))
    soscalls, sosmean, sosvar = eval_ecall(sos)

    # Adjust ocall mean by removing ecall latency and adding variances
    sosmean = sosmean - semean
    sosvar  = sosvar + sevar
    print_time("SGXJail O", sosmean, sosvar)

    # Reload ECALL benchmarks with cpufreq
    ve = load_ecall(cpufreq, 'vanilla_ecalls_{}.csv'.format(eocalls))
    vecalls, vemean, vevar = eval_ecall(ve)
    se = load_ecall(cpufreq, 'sbox_ecalls_{}.csv'.format(eocalls))
    secalls, semean, sevar = eval_ecall(se)

    if ocalls:
        # Runtime of synthetic workload without any OCALL
        baseline = load_ocall(cpufreq, 'vanilla_ocallsBaseline_{}.csv'.format(ocalls))
        bmean, bvar = eval_ocall(baseline, vemean, vevar)
        print_time("Vanilla Ocall Baseline", bmean, bvar)

        # Evaluate OCALL benchmarks with cpufreq
        vo = load_ocall(cpufreq, 'vanilla_ocalls_{}.csv'.format(ocalls))
        vomean, vovar = eval_ocall(vo, vemean, vevar)
        vostd = vovar.apply(np.sqrt)


        so = load_ocall(cpufreq, 'sbox_ocalls_{}.csv'.format(ocalls))
        somean, sovar = eval_ocall(so, semean, sevar)
        sostd = sovar.apply(np.sqrt)

        # Absolute overhead of SGXJail over Vanilla runtimes
        (overhead, overheadvar) = compute_overhead(vomean, vovar, somean, sovar)
        overheadstd = overheadvar.apply(np.sqrt)

        # Runtime overhead over baseline
        vomeanrel, vovarrel = compute_ratio(float(bmean), float(bvar), vomean, vovar)
        vostdrel = vovarrel.apply(np.sqrt)
        someanrel, sovarrel = compute_ratio(float(bmean), float(bvar), somean, sovar)
        sostdrel = sovarrel.apply(np.sqrt)
        vomeanrel = vomeanrel - 1
        someanrel = someanrel - 1

        result = pd.concat([vomean, somean], axis=1)
        resultvar = pd.concat([vovar, sovar], axis=1)
        #result.columns = ['Vanilla', 'Sandbox']
        #result.plot(title='Runtime in ticks', style='-*', yerr=resultvar, logx=True, logy=False)
        ocall_ylabel = 'Runtime in ' + 's' if freq else 'ticks'
        if True:  # Plot base
            vomean = vomeanrel
            vovar = vovarrel
            vostd = vostdrel
            somean = someanrel
            sovar = sovarrel
            sostd = sostdrel
            ocall_ylabel = 'App/enclave ratio'
            
        fig, ax1 = plt.subplots()
        ax1.plot(vomean.index / float(bmean), vomean, 'bD-', label='Vanilla')
        ax1.fill_between(vomean.index / float(bmean), (vomean - vostd).squeeze(), (vomean + vostd).squeeze(), color='b', alpha=0.2)
        ax1.plot(somean.index / float(bmean), somean, 'gv--', label='SGXJail')
        ax1.fill_between(somean.index / float(bmean), (somean - sostd).squeeze(), (somean + sostd).squeeze(), color='g', alpha=0.2)
        ax1.set_xscale('log')
        ax1.set_ylabel(ocall_ylabel)
        ax1.set_xlabel('OCALLs / Esec')
        ax1.legend(loc=0)

        #overhead.plot(title='Runtime overhead in %', style='-*', logx=True, logy=False)

        ax2 = ax1.twinx()
        ax2.plot(overhead.index / float(bmean), overhead, 'ro-.', label='Overhead')
        ax2.fill_between(overhead.index / float(bmean), (overhead - overheadstd).squeeze(), (overhead + overheadstd).squeeze(), color='r', alpha=0.2)
        ax2.set_ylabel('SGXJail/Vanilla in \%')
        ax2.legend(bbox_to_anchor=(0.85,0.97))

        export_tikz('fig/ocalls.tex', figureheight='0.8\\hsize', figurewidth='\\hsize')
        ax1.set_title('Ocall performance')

    if pfsvanilla and pfssbox:
        # Evaluate PFS
        pfslist = []
        for subdir, dirs, files in os.walk(pfsvanilla):
            for f in files:
                filename = os.path.join(subdir, f)
                pfslist.append(load_pfs_csv(cpufreq, filename))
        assert(len(pfslist) > 1)
        vpfs = pfslist[0].append(pfslist[1:])
        (vpfsmean, vpfsvar) = eval_pfs(vpfs, vemean, vevar)
        vpfsstd = vpfsvar.apply(np.sqrt)

        pfslist = []
        for subdir, dirs, files in os.walk(pfssbox):
            for f in files:
                filename = os.path.join(subdir, f)
                pfslist.append(load_pfs_csv(cpufreq, filename))
        assert(len(pfslist) > 1)
        spfs = pfslist[0].append(pfslist[1:])
        (spfsmean, spfsvar) = eval_pfs(spfs, semean, sevar)
        spfsstd = spfsvar.apply(np.sqrt)

        # Compute overhead
        (pfsoverhead, pfsoverheadvar) = compute_overhead(vpfsmean, vpfsvar, spfsmean, spfsvar)
        pfsoverheadstd = pfsoverheadvar.apply(np.sqrt)
        
        #~ plt.figure()
        #~ plt.plot(vpfsmean.index, vpfsmean, 'bD-')
        #~ plt.fill_between(vpfsmean.index, (vpfsmean - vpfsstd).squeeze(), (vpfsmean + vpfsstd).squeeze(), color='b', alpha=0.2)
        #~ plt.plot(spfsmean.index, spfsmean, 'gv--')
        #~ plt.fill_between(spfsmean.index, (spfsmean - spfsstd).squeeze(), (spfsmean + spfsstd).squeeze(), color='g', alpha=0.2)
        #~ plt.title('PFS performance')
        #~ plt.legend(['Vanilla', 'SGXJail'])
        #~ plt.xscale('log')
        #~ plt.ylabel('Runtime in ' + 'sec' if freq else 'ticks')
        #~ plt.xlabel('Chunk size for 1MB block')
        #~ export_tikz('fig/pfs.tex', figureheight='0.8\\hsize', figurewidth='\\hsize')

        # Plot runtime over different payload sizes
        fig, ax1 = plt.subplots()
        chunks = 1
        plot_pfs_chunks(ax1, vpfsmean, vpfsvar, vpfsstd, chunks, fmt='D-', color='b')
        plot_pfs_chunks(ax1, spfsmean, spfsvar, spfsstd, chunks, fmt='v--', color='g')
        pfsoverhead = pfsoverhead.filter_by({'OWRITE':[chunks]})
        pfsidx = pfsoverhead.index.get_level_values('PAYLOAD')
        pfsoverheadstd = pfsoverheadstd.filter_by({'OWRITE':[chunks]})

        #plot_pfs_chunks(vpfsmean, vpfsvar, vpfsstd, 4096)
        #plot_pfs_chunks(spfsmean, spfsvar, spfsstd, 4096)
        #plt.legend(['Vanilla 1 chunk', 'Sandbox 1 chunk', 'Vanilla 4096 chunks', 'Sandbox 4096 chunks'])
        ax1.legend(['Vanilla', 'SGXJail'])
        ax1.set_xscale('log')
        ax1.set_yscale('log')

        # for linear representation
        #ax1.set_xlabel('Payload size in MB')
        #x = np.array([0, 0.2, 0.4, 0.6, 0.8, 1.0])
        #xt = ['{:1.1f}'.format(xx) for xx in x]
        #ax1.set_xticks(x * 1024 * 1024, xt)
        #ax1.set_ylabel('Runtime in msec')
        #y = np.array([0, 2, 4, 6, 8, 10, 12])
        #yt = ['{:2.0f}'.format(yy) for yy in y]
        #ax1.set_yticks(y / 1000, yt)

        # for log representation
        ax1.set_xlabel('Payload size in bytes')
        ax1.set_ylabel('Runtime in msec')

        # Install a custom formatter that scales axis labels by 1k
        # Doesn't work for tikz
        def yformatter(x, pos):
            return '%.1f' % (x * 1000)

        ax1.yaxis.set_major_formatter(plt.FuncFormatter(yformatter))

        # Plot overhead
        if True:
            ax2 = ax1.twinx()
            ax2.plot(pfsidx, pfsoverhead, 'ro-.', label='Overhead')
            ax2.fill_between(pfsidx, (pfsoverhead - pfsoverheadstd).squeeze(), (pfsoverhead + pfsoverheadstd).squeeze(), color='r', alpha=0.2)
            ax2.set_ylabel('Overhead in \%')
            ax2.set_ylim(-10, 110, auto=False)
            ax2.legend(bbox_to_anchor=(0.9, 1))

        export_tikz('fig/pfs.tex', figureheight='0.8\\hsize', figurewidth='\\hsize')
        ax1.set_title('PFS performance over different payload sizes')

        #~ # Plot overhead over different payload sizes
        #~ plt.figure()
        #~ chunks = sorted(set(spfsmean.index.get_level_values('OWRITE')))
        #~ for i in chunks:
            #~ plot_pfs_chunks(pfsoverhead, pfsoverheadvar, pfsoverheadstd, i)
        #~ plt.title('PFS overhead over different payload sizes')
        #~ plt.xscale('log')
        #~ plt.legend(["{} chunks".format(i) for i in chunks])
        #~ plt.ylabel('Overhead in \%')
        #~ plt.xlabel('Payload size')

        #~ # Plot runtime over different number of chunks
        #~ plt.figure()
        #~ plot_pfs_payload(vpfsmean, vpfsvar, vpfsstd, 1024)
        #~ plot_pfs_payload(spfsmean, spfsvar, spfsstd, 1024)
        #~ plot_pfs_payload(vpfsmean, vpfsvar, vpfsstd, 1024*1024)
        #~ plot_pfs_payload(spfsmean, spfsvar, spfsstd, 1024*1024)
        #~ plt.title('PFS performance over different number of chunks')
        #~ plt.legend(['Vanilla 1KB', 'Sandbox 1KB', 'Vanilla 1MB', 'Sandbox 1MB'])
        #~ plt.xscale('log')
        #~ plt.xlabel('Number of Chunks')

       #~ # Plot overhead over different number of chunks
        #~ plt.figure()
        #~ payloads = sorted(set(spfsmean.index.get_level_values('PAYLOAD')))
        #~ for i in payloads:
            #~ # Plot absolute runtime
            #~ #plot_pfs_payload(vpfsmean, vpfsvar, vpfsstd, i)
            #~ # Plot overhead
            #~ plot_pfs_payload(pfsoverhead, pfsoverheadvar, pfsoverheadstd, i)

        #~ plt.title('PFS overhead over different number of chunks')
        #~ plt.xscale('log')
        #~ plt.legend(["{} payload".format(i) for i in chunks])
        #~ plt.ylabel('Overhead in \%')
        #~ plt.xlabel('Number of Chunks')

    if show:
        plt.show()

if __name__ == "__main__":
    main(obj={})
