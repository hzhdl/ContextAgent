#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
合约指令覆盖率分析与可视化模块
用于统计和绘制嵌入合约指令、已覆盖指令和未覆盖指令的PC分布
"""

import os
import time
from typing import List, Dict, Set, Any
import matplotlib
matplotlib.use('Agg')  # 非交互式后端
import matplotlib.pyplot as plt
import numpy as np
plt.rcParams['font.sans-serif'] = ['SimHei','WenQuanYi Zen Hei']
plt.rcParams['axes.unicode_minus'] = False

class CoverageAnalyzer:
    """
    覆盖率分析器，负责采集覆盖率数据并生成可视化图表
    """

    def __init__(self):
        """初始化分析器"""
        self.snapshots = []  # 时间序列快照列表
        self.start_time = time.time()  # 记录开始时间

    def capture_snapshot(self, overall_pcs: List[int], code_coverage: Set[str],
                        embedded_stats: Dict[str, Any]) -> None:
        """
        采集当前覆盖率状态快照

        参数:
            overall_pcs: 所有指令的PC列表（整数）
            code_coverage: 已覆盖指令的PC集合（十六进制字符串）
            embedded_stats: 嵌入合约统计信息，包含 'total_pcs' 和 'covered_pcs'
        """
        current_time = time.time() - self.start_time

        # 转换PC格式：确保一致性
        all_pcs_set = set(hex(pc) for pc in overall_pcs)
        covered_pcs_set = set(code_coverage)

        # 嵌入合约PC
        embedded_total_pcs = set(embedded_stats.get('total_pcs', set()))
        embedded_covered_pcs = set(embedded_stats.get('covered_pcs', set()))

        # 计算统计数据
        total_count = len(overall_pcs)
        covered_count = len(covered_pcs_set)
        uncovered_count = total_count - covered_count

        # 计算原始覆盖率
        raw_coverage_percentage = (covered_count / total_count * 100) if total_count > 0 else 0

        # 计算校正后的覆盖率（排除未覆盖的嵌入合约指令）
        embedded_total_count = len(embedded_total_pcs)
        embedded_covered_count = len(embedded_covered_pcs)
        corrected_total = total_count - (embedded_total_count - embedded_covered_count)
        corrected_coverage_percentage = (covered_count / corrected_total * 100) if corrected_total > 0 else 0

        snapshot = {
            'time': current_time,
            'all_pcs': list(overall_pcs),
            'covered_pcs': list(covered_pcs_set),
            'uncovered_pcs': list(all_pcs_set - covered_pcs_set),
            'embedded_total_pcs': list(embedded_total_pcs),
            'embedded_covered_pcs': list(embedded_covered_pcs),
            'total_count': total_count,
            'covered_count': covered_count,
            'uncovered_count': uncovered_count,
            'embedded_total_count': embedded_total_count,
            'embedded_covered_count': embedded_covered_count,
            'corrected_total': corrected_total,
            'raw_coverage_percentage': raw_coverage_percentage,
            'corrected_coverage_percentage': corrected_coverage_percentage
        }

        self.snapshots.append(snapshot)

    def plot_pc_distribution(self, output_path: str) -> None:
        """
        绘制PC空间分布图

        在一个图上显示所有PC值的覆盖状态：
        - 绿色：已覆盖的指令
        - 红色：未覆盖的指令
        - 蓝色：嵌入合约的指令

        参数:
            output_path: 输出PNG文件路径
        """
        if not self.snapshots:
            print("警告：没有可用的覆盖率快照，跳过PC分布图生成")
            return

        # 使用最后一个快照的数据
        final_snapshot = self.snapshots[-1]

        # 转换PC值为整数并排序
        all_pcs = sorted([int(pc, 16) if isinstance(pc, str) else pc for pc in final_snapshot['all_pcs']])
        covered_pcs = set([int(pc, 16) if isinstance(pc, str) else pc for pc in final_snapshot['covered_pcs']])
        embedded_pcs = set([int(pc, 16) if isinstance(pc, str) else pc for pc in final_snapshot['embedded_total_pcs']])

        # 分类PC
        covered_non_embedded = []
        uncovered_non_embedded = []
        embedded_list = []

        for pc in all_pcs:
            if pc in embedded_pcs:
                embedded_list.append(pc)
            elif pc in covered_pcs:
                covered_non_embedded.append(pc)
            else:
                uncovered_non_embedded.append(pc)

        # 创建图表
        fig, ax = plt.subplots(figsize=(14, 6))

        # 绘制散点图
        if covered_non_embedded:
            ax.scatter(covered_non_embedded, [1]*len(covered_non_embedded),
                      c='green', marker='|', s=100, label=f'已覆盖 ({len(covered_non_embedded)})', alpha=0.7)

        if uncovered_non_embedded:
            ax.scatter(uncovered_non_embedded, [0]*len(uncovered_non_embedded),
                      c='red', marker='|', s=100, label=f'未覆盖 ({len(uncovered_non_embedded)})', alpha=0.7)

        if embedded_list:
            ax.scatter(embedded_list, [0.5]*len(embedded_list),
                      c='blue', marker='|', s=100, label=f'嵌入合约 ({len(embedded_list)})', alpha=0.5)

        # 设置图表属性
        ax.set_xlabel('程序计数器 (PC)', fontsize=12)
        ax.set_ylabel('覆盖状态', fontsize=12)
        ax.set_title('合约指令PC空间分布图', fontsize=14, fontweight='bold')
        ax.set_yticks([0, 0.5, 1])
        ax.set_yticklabels(['未覆盖', '嵌入合约', '已覆盖'])
        ax.legend(loc='upper right')
        ax.grid(True, alpha=0.3, axis='x')

        # 添加统计信息
        stats_text = f'总指令数: {len(all_pcs)}\n'
        stats_text += f'覆盖率: {final_snapshot["raw_coverage_percentage"]:.2f}%\n'
        stats_text += f'校正覆盖率: {final_snapshot["corrected_coverage_percentage"]:.2f}%'
        ax.text(0.02, 0.98, stats_text, transform=ax.transAxes,
               fontsize=10, verticalalignment='top',
               bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"PC分布图已保存到: {output_path}")

    def plot_coverage_statistics(self, output_path: str) -> None:
        """
        绘制指令数量统计柱状图

        展示两组对比：原始统计 vs 校正后统计
        每组包含：总指令数、已覆盖、未覆盖

        参数:
            output_path: 输出PNG文件路径
        """
        if not self.snapshots:
            print("警告：没有可用的覆盖率快照，跳过统计图生成")
            return

        # 使用最后一个快照的数据
        final_snapshot = self.snapshots[-1]

        # 原始统计数据
        raw_total = final_snapshot['total_count']
        raw_covered = final_snapshot['covered_count']
        raw_uncovered = final_snapshot['uncovered_count']
        raw_coverage_pct = final_snapshot['raw_coverage_percentage']

        # 校正后统计数据
        corrected_total = final_snapshot['corrected_total']
        corrected_covered = raw_covered  # 已覆盖数量不变
        corrected_uncovered = corrected_total - corrected_covered
        corrected_coverage_pct = final_snapshot['corrected_coverage_percentage']

        # 嵌入合约统计
        embedded_total = final_snapshot['embedded_total_count']
        embedded_covered = final_snapshot['embedded_covered_count']
        embedded_uncovered = embedded_total - embedded_covered

        # 创建图表
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

        # 左图：原始统计
        categories = ['总指令数', '已覆盖', '未覆盖']
        values_raw = [raw_total, raw_covered, raw_uncovered]
        colors_raw = ['#4472C4', '#70AD47', '#C55A5A']

        bars1 = ax1.bar(categories, values_raw, color=colors_raw, alpha=0.8, edgecolor='black')
        ax1.set_ylabel('指令数量', fontsize=12)
        ax1.set_title(f'原始统计\n覆盖率: {raw_coverage_pct:.2f}%', fontsize=13, fontweight='bold')
        ax1.grid(True, alpha=0.3, axis='y')

        # 在柱状图上添加数值标签
        for bar in bars1:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}',
                    ha='center', va='bottom', fontsize=10)

        # 右图：校正后统计
        values_corrected = [corrected_total, corrected_covered, corrected_uncovered]
        colors_corrected = ['#4472C4', '#70AD47', '#C55A5A']

        bars2 = ax2.bar(categories, values_corrected, color=colors_corrected, alpha=0.8, edgecolor='black')
        ax2.set_ylabel('指令数量', fontsize=12)
        ax2.set_title(f'校正后统计（排除未覆盖的嵌入合约）\n覆盖率: {corrected_coverage_pct:.2f}%',
                     fontsize=13, fontweight='bold')
        ax2.grid(True, alpha=0.3, axis='y')

        # 在柱状图上添加数值标签
        for bar in bars2:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}',
                    ha='center', va='bottom', fontsize=10)

        # 添加嵌入合约信息
        if embedded_total > 0:
            info_text = f'嵌入合约指令:\n总数: {embedded_total}\n已覆盖: {embedded_covered}\n未覆盖: {embedded_uncovered}'
            fig.text(0.5, 0.02, info_text, ha='center', fontsize=10,
                    bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.5))

        plt.suptitle('合约指令覆盖率统计对比', fontsize=15, fontweight='bold', y=0.98)
        plt.tight_layout(rect=[0, 0.08, 1, 0.95])
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"统计图已保存到: {output_path}")

    def plot_coverage_trend(self, output_path: str) -> None:
        """
        绘制覆盖率随时间变化的趋势图

        展示两条曲线：
        - 原始覆盖率
        - 校正后覆盖率

        参数:
            output_path: 输出PNG文件路径
        """
        if not self.snapshots:
            print("警告：没有可用的覆盖率快照，跳过趋势图生成")
            return

        # 提取时间序列数据
        times = [snapshot['time'] for snapshot in self.snapshots]
        raw_coverages = [snapshot['raw_coverage_percentage'] for snapshot in self.snapshots]
        corrected_coverages = [snapshot['corrected_coverage_percentage'] for snapshot in self.snapshots]

        # 创建图表
        fig, ax = plt.subplots(figsize=(12, 6))

        # 绘制两条曲线
        ax.plot(times, raw_coverages, label='原始覆盖率',
               color='#4472C4', linewidth=2, marker='o', markersize=3, alpha=0.7)
        ax.plot(times, corrected_coverages, label='校正后覆盖率',
               color='#70AD47', linewidth=2, marker='s', markersize=3, alpha=0.7)

        # 设置图表属性
        ax.set_xlabel('时间 (秒)', fontsize=12)
        ax.set_ylabel('覆盖率 (%)', fontsize=12)
        ax.set_title('合约指令覆盖率随时间变化趋势', fontsize=14, fontweight='bold')
        ax.legend(loc='lower right', fontsize=11)
        ax.grid(True, alpha=0.3)
        ax.set_ylim([0, 105])  # 设置y轴范围为0-105%

        # 添加最终覆盖率标注
        if times and raw_coverages:
            final_time = times[-1]
            final_raw = raw_coverages[-1]
            final_corrected = corrected_coverages[-1]

            stats_text = f'最终统计 (t={final_time:.2f}s):\n'
            stats_text += f'原始覆盖率: {final_raw:.2f}%\n'
            stats_text += f'校正覆盖率: {final_corrected:.2f}%'

            ax.text(0.02, 0.98, stats_text, transform=ax.transAxes,
                   fontsize=10, verticalalignment='top',
                   bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))

        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"趋势图已保存到: {output_path}")

    def generate_all_plots(self, contract_name: str, output_dir: str = "./") -> None:
        """
        生成所有可视化图表

        参数:
            contract_name: 合约名称，用于生成文件名
            output_dir: 输出目录路径
        """
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)

        # 生成文件路径
        pc_dist_path = os.path.join(output_dir, f"{contract_name}_pc_distribution.png")
        stats_path = os.path.join(output_dir, f"{contract_name}_coverage_stats.png")
        trend_path = os.path.join(output_dir, f"{contract_name}_coverage_trend.png")

        # 生成三种图表
        print(f"\n开始生成覆盖率可视化图表...")
        print(f"合约名称: {contract_name}")
        print(f"快照数量: {len(self.snapshots)}")

        self.plot_pc_distribution(pc_dist_path)
        self.plot_coverage_statistics(stats_path)
        self.plot_coverage_trend(trend_path)

        print(f"\n所有图表已生成完毕！")
        print(f"输出目录: {output_dir}")
