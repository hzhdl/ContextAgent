#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' Genetic Algorithm engine definition '''

import math
import time
import logging
import random

from functools import wraps

# Imports for profiling.
import cProfile
import pstats
import os

import numpy as np
from utils import settings


from .components import Individual, Population
from .plugin_interfaces.operators import Selection, Crossover, Mutation
from .plugin_interfaces.analysis import OnTheFlyAnalysis

def do_profile(filename, sortby='tottime'):
    '''
    Constructor for function profiling decorator.
    '''
    def _do_profile(func):
        '''
        Function profiling decorator.
        '''
        @wraps(func)
        def profiled_func(*args, **kwargs):
            '''
            Decorated function.
            '''
            # Flag for doing profiling or not.
            DO_PROF = os.getenv('PROFILING')

            if DO_PROF:
                profile = cProfile.Profile()
                profile.enable()
                result = func(*args, **kwargs)
                profile.disable()
                ps = pstats.Stats(profile).sort_stats(sortby)
                ps.dump_stats(filename)
            else:
                result = func(*args, **kwargs)
            return result
        return profiled_func

    return _do_profile


class StatVar(object):
    def __init__(self, name):
        '''
        Descriptor for statistical variables which need to be memoized when
        engine is running.
        '''
        # Protected.
        self.name = '_{}'.format(name)

    def __get__(self, engine, cls):
        '''
        Getter.
        '''
        stat_var = getattr(engine, self.name)
        if stat_var is None:
            if 'min' in self.name and 'ori' in self.name:
                stat_var = engine.population.min(engine.ori_fitness)
            elif 'min' in self.name:
                stat_var = engine.population.min(engine.fitness)
            elif 'max' in self.name and 'ori' in self.name:
                stat_var = engine.population.max(engine.ori_fitness)
            elif 'max' in self.name:
                stat_var = engine.population.max(engine.fitness)
            elif 'mean' in self.name and 'ori' in self.name:
                stat_var = engine.population.mean(engine.ori_fitness)
            elif 'mean' in self.name:
                stat_var = engine.population.mean(engine.fitness)
            setattr(engine, self.name, stat_var)
        return stat_var

    def __set__(self, engine, value):
        '''
        Setter.
        '''
        setattr(engine, self.name, value)


class EvolutionaryFuzzingEngine(object):
    # Statistical attributes for population.
    fmax, fmin, fmean = StatVar('fmax'), StatVar('fmin'), StatVar('fmean')
    ori_fmax, ori_fmin, ori_fmean = (StatVar('ori_fmax'),
                                     StatVar('ori_fmin'),
                                     StatVar('ori_fmean'))

    def __init__(self, population:Population, selection, crossover, mutation, fitness=None, analysis=None, mapping=None):
        # Set logger.
        logger_name = 'engine.{}'.format(self.__class__.__name__)
        self.logger = logging.getLogger(logger_name)

        # Attributes assignment.
        self.population = population
        self.fitness = fitness
        self.selection = selection
        self.crossover = crossover
        self.mutation = mutation
        self.analysis = [] if analysis is None else [a() for a in analysis]
        self.mapping = mapping

        # Maxima and minima in population.
        self._fmax, self._fmin, self._fmean = None, None, None
        self._ori_fmax, self._ori_fmin, self._ori_fmean = None, None, None

        # Default fitness functions.
        self.ori_fitness = None if self.fitness is None else self.fitness

        # Store current generation number.
        self.current_generation = -1  # Starts from 0.

        # Check parameters validity.
        self._check_parameters()

    def cal_fitness(self,res_ind):
        if not settings.MUTATE_ENERGY_ENABLE:
            judge_bran = 1 if res_ind["unbranlens"] < res_ind["unbranlens_pre"]  else 0
            return judge_bran
        #TODO: 选取合适的解加入种子池
        bran_covs = res_ind["unbranlens_pre"] -res_ind["unbranlens"]
        mock_detect_call_success = res_ind["mock_detect_call_success"]
        mock_detect_call_fail = res_ind["mock_detect_call_fail"]

        # 多级能量计算
        # 一级变异能量
        judge_bran = 1 if res_ind["unbranlens"] < res_ind["unbranlens_pre"]  else 0
        judge_vul = 1 if np.mean(res_ind["vul_w"]) < 0.995 else 0
        judge_cri = 1 if len(res_ind["cri_opc"])>0 else 0
        judge_energy = judge_bran + judge_vul + judge_cri

        return judge_energy

    @do_profile(filename='engine_run.prof')
    def run(self, ng):
        '''
        Run the fuzzing optimization iteration with coverage-guided seed scheduling.

        New flow (refactored):
        1. Batch execute current population via register_step
        2. Select advantage seeds (top 50%-67% by adaptive threshold)
        3. Energy-driven mutation on advantage seeds using stored res_ind
        4. Population update (merge + sort + filter to population size)
        5. Elite injection (periodic)
        6. Population reset (on stagnation)

        Note: Selection and crossover operations are temporarily disabled but preserved
        in code comments for potential future use.
        '''
        try:
            execution_begin = time.time()
            self.analysis[0].env.execseeds_count = 0
            self.analysis[0].env.fitseeds_count = 0

            if self.fitness is None:
                raise AttributeError('No fitness function in GA engine')

            # Setup analysis objects
            for a in self.analysis:
                a.setup(ng=ng, engine=self)

            generation = 0

            # Main generational loop
            while generation < ng or settings.GLOBAL_TIMEOUT:
                if settings.GLOBAL_TIMEOUT and time.time() - execution_begin >= settings.GLOBAL_TIMEOUT:
                    break

                self.current_generation = generation
                self.logger.info(f"Generation {generation}: Population size = {len(self.population.individuals)}")

                # ===== STEP 1: BATCH EXECUTION via register_step =====
                # Execute all individuals, calculate fitness, store res_ind
                for a in self.analysis:
                    if generation % a.interval == 0:
                        a.register_step(g=generation, population=self.population, engine=self)

                # print(len(self.population.individuals),"--------------")
                # ===== STEP 2: SELECT ADVANTAGE SEEDS =====
                # Select top 50%-67% individuals by adaptive threshold
                advantage_seeds = []
                if len(self.population.individuals) > 0 and self.fitness:
                    # Calculate adaptive threshold
                    adaptive_threshold = self.analysis[0].calculate_adaptive_threshold()

                    # Sort by fitness
                    sorted_individuals = sorted(
                        self.population.individuals,
                        key=lambda x: x.res_ind["fitness"] if x.res_ind and hasattr(x.res_ind,"fitness") else 0,
                        # key=lambda x: self.cal_fitness(x.res_ind) if x.res_ind else 0,
                        reverse=True
                    )
                    if not settings.MUTATE_ENERGY_ENABLE:
                        advantage_seeds = [
                            indv for indv in sorted_individuals
                            if self.fitness(indv) >= 0
                        ]
                        
                    else:
                        # Filter by adaptive threshold
                        advantage_seeds = [
                            indv for indv in sorted_individuals
                            # if self.fitness(indv) >= adaptive_threshold
                            if indv.res_ind and hasattr(indv.res_ind,"fitness") and indv.res_ind["fitness"] >= adaptive_threshold
                        ]
                        # Apply quantity limits: min 50%, max 67%
                        # 默认使用2/3
                        min_count = max(1, len(sorted_individuals) // 2)
                        max_count = max(1, int(len(sorted_individuals) * 2 / 3))
                        

                        if len(advantage_seeds) < min_count:
                            advantage_seeds = sorted_individuals[:min_count]
                            self.logger.debug(f"Advantage seeds below minimum, selected top {min_count}")

                        if len(advantage_seeds) > max_count:
                            # Too many seeds, limit to max_count
                            advantage_seeds = advantage_seeds[:max_count]
                    

                # ===== STEP 3: ENERGY-DRIVEN MUTATION on advantage seeds =====
                # Perform energy-driven mutation FIRST (more targeted, priority)
                all_mutants = []
                for seed in advantage_seeds:
                    # Use stored res_ind for energy-driven mutation
                    if hasattr(seed, 'res_ind') and seed.res_ind is not None:
                        # Calculate energies from stored res_ind
                        parameter_energy, state_energy, environment_energy = \
                            self.analysis[0].calculate_adaptive_energies(seed.res_ind)

                        # Prepare energy vector for mutation
                        energy = [state_energy, parameter_energy, 0.2, environment_energy]
                        # print(energy)
                        if not settings.MUTATE_ENERGY_ENABLE:
                            all_mutants.extend([seed.clone()])
                        else:
                            # Generate mutants using energy-driven mutation
                            mutants = self.mutation.mutate_fundis(
                                seed, seed.res_ind,
                                off_mutate_history=True,
                                energy=energy
                            )
                            
                            all_mutants.extend(mutants)
                    # else:
                    #     print("wrong")

                mutation_offspring = all_mutants
                self.logger.info(f"Generated {len(mutation_offspring)} mutants from {len(advantage_seeds)} advantage seeds")

                # ===== STEP 3.5: ELITE-BASED CROSSOVER (COMPLEMENTARY) =====
                # Perform crossover on mutation offspring (two-stage evolution)
                crossover_offspring = []
                if settings.CROSSOVER_ENABLE and len(mutation_offspring) >= 2:
                    # Calculate number of crossover pairs based on mutation offspring count
                    # Target 1:1 ratio means crossover_offspring ≈ mutation_offspring
                    # Each pair produces 2 children, so pairs = mutation_count * ratio / 2
                    crossover_pairs = int((len(sorted_individuals) - len(mutation_offspring)) / 2)
                    # crossover_pairs = int(len(mutation_offspring) / 4)

                    # Limit: cannot exceed number of mutation_offspring
                    crossover_pairs = min(crossover_pairs, len(mutation_offspring))
                    crossover_pairs = max(1, crossover_pairs)  # At least 1 pair

                    # Create temporary Population from mutation offspring for selection
                    from engine.components import Population
                    mini_pop = Population(
                        indv_template=self.population.indv_template,
                        indv_generator=self.population.indv_generator,
                        size=len(mutation_offspring)
                    )
                    mini_pop.individuals = mutation_offspring

                    # Perform crossover on mutated individuals
                    for _ in range(crossover_pairs):
                        try:
                            father, mother = self.selection.select(mini_pop, self.fitness)

                            # Use crossover probability
                            # if random.random() <= settings.PROBABILITY_CROSSOVER:
                            child1, child2 = self.crossover.cross(father, mother)
                            child1.res_ind = None
                            child2.res_ind = None
                            crossover_offspring.extend([child1, child2])
                        except Exception as e:
                            self.logger.warning(f"Crossover failed: {e}")
                            continue

                    self.logger.info(f"Generated {len(crossover_offspring)} offspring via crossover from {crossover_pairs} pairs of mutated individuals")

                # ===== STEP 4: POPULATION UPDATE =====
                # Merge mutation and crossover offspring
                all_offspring = mutation_offspring + crossover_offspring
                # print(len(mutation_offspring),len(crossover_offspring),"--------------")

                # Log offspring statistics
                total_offspring = len(all_offspring)
                if total_offspring > 0:
                    mutation_pct = len(mutation_offspring) / total_offspring * 100
                    crossover_pct = len(crossover_offspring) / total_offspring * 100
                    self.logger.info(
                        f"Total offspring: {total_offspring} "
                        f"(mutation: {len(mutation_offspring)} [{mutation_pct:.1f}%], "
                        f"crossover: {len(crossover_offspring)} [{crossover_pct:.1f}%])"
                    )

                # Directly replace population with all offspring (no merge, no sort)
                # Offspring will be executed and evaluated in the next generation
                self.population.individuals = all_offspring

                # Adjust population size
                IndvType = self.population.indv_template.__class__
                if len(self.population.individuals) < self.population.size:
                    # Fill if under-populated
                    while len(self.population.individuals) < self.population.size:
                        new_ind = IndvType(generator=self.population.indv_generator).init()
                        self.population.individuals.append(new_ind)
                # elif len(self.population.individuals) > self.population.size:
                    # Truncate if over-populated
                    # self.population.individuals = self.population.individuals[:self.population.size]

                # ===== STEP 5: ELITE INJECTION (periodic) =====
                if generation > 0 and generation % settings.ELITE_INJECTION_INTERVAL == 0:
                    if hasattr(self.population, 'get_elite_seeds'):
                        elite_seeds = self.population.get_elite_seeds(settings.ELITE_INJECTION_COUNT)
                        for elite in elite_seeds:
                            if len(self.population.individuals) > 0:
                                # Replace worst individual
                                worst_idx = min(
                                    range(len(self.population.individuals)),
                                    key=lambda i: self.fitness(self.population.individuals[i]) if self.fitness else 0
                                )
                                self.population.individuals[worst_idx] = elite
                        self.logger.info(f"Elite injection at generation {generation}: injected {len(elite_seeds)} elites")

                generation += 1

        except Exception as e:
            # Log exception info
            msg = '{} exception is catched'.format(type(e).__name__)
            self.logger.exception(msg)
            raise e
        finally:
            # Perform the analysis post processing
            self.logger.info(f"Final population size: {len(self.population.individuals)}")
            for a in self.analysis:
                a.finalize(population=self.population, engine=self)

    def _update_statvars(self):
        '''
        Private helper function to update statistic variables in GA engine, like
        maximum, minimum and mean values.
        '''
        # Wrt original fitness.
        self.ori_fmax = self.population.max(self.ori_fitness)
        self.ori_fmin = self.population.min(self.ori_fitness)
        self.ori_fmean = self.population.mean(self.ori_fitness)

        # Wrt decorated fitness.
        self.fmax = self.population.max(self.fitness)
        self.fmin = self.population.min(self.fitness)
        self.fmean = self.population.mean(self.fitness)

    def _check_parameters(self):
        '''
        Helper function to check parameters of engine.
        '''
        if not isinstance(self.population, Population):
            raise TypeError('population must be a Population object')
        if not isinstance(self.selection, Selection):
            raise TypeError('selection operator must be a Selection instance')
        if not isinstance(self.crossover, Crossover):
            raise TypeError('crossover operator must be a Crossover instance')
        if not isinstance(self.mutation, Mutation):
            raise TypeError('mutation operator must be a Mutation instance')

        for ap in self.analysis:
            if not isinstance(ap, OnTheFlyAnalysis):
                msg = '{} is not subclass of OnTheFlyAnalysis'.format(ap.__name__)
                raise TypeError(msg)

    # Decorators.

    def fitness_register(self, fn):
        '''
        A decorator for fitness function register.
        '''
        @wraps(fn)
        def _fn_with_fitness_check(indv):
            '''
            A wrapper function for fitness function with fitness value check.
            '''
            # Check indv type.
            if not isinstance(indv, Individual):
                raise TypeError('indv\'s class must be Individual or a subclass of Individual')

            # Check fitness.
            fitness = fn(indv)
            is_invalid = (type(fitness) is not float) or (math.isnan(fitness))
            if is_invalid:
                msg = 'Fitness value(value: {}, type: {}) is invalid'
                msg = msg.format(fitness, type(fitness))
                raise ValueError(msg)
            return fitness

        self.fitness = _fn_with_fitness_check
        if self.ori_fitness is None:
            self.ori_fitness = _fn_with_fitness_check

    def analysis_register(self, analysis_cls):
        '''
        A decorator for analysis regsiter.
        '''
        if not issubclass(analysis_cls, OnTheFlyAnalysis):
            raise TypeError('analysis class must be subclass of OnTheFlyAnalysis')

        # Add analysis instance to engine.
        analysis = analysis_cls()
        self.analysis.append(analysis)

    # Functions for fitness scaling.

    def linear_scaling(self, target='max', ksi=0.5):
        '''
        A decorator constructor for fitness function linear scaling.

        :param target: The optimization target, maximization or minimization.
        :type target: str, 'max' or 'min'

        :param ksi: Selective pressure adjustment value.
        :type ksi: float

        Linear Scaling:
            1. arg max f(x), then f' = f - min{f(x)} + ksi;
            2. arg min f(x), then f' = max{f(x)} - f(x) + ksi;
        '''
        def _linear_scaling(fn):
            # For original fitness calculation.
            self.ori_fitness = fn

            @wraps(fn)
            def _fn_with_linear_scaling(indv):
                # Original fitness value.
                f = fn(indv)

                # Determine the value of a and b.
                if target == 'max':
                    f_prime = f - self.ori_fmin + ksi
                elif target == 'min':
                    f_prime = self.ori_fmax - f + ksi
                else:
                    raise ValueError('Invalid target type({})'.format(target))
                return f_prime

            return _fn_with_linear_scaling

        return _linear_scaling

    def dynamic_linear_scaling(self, target='max', ksi0=2, r=0.9):
        '''
        A decorator constructor for fitness dynamic linear scaling.

        :param target: The optimization target, maximization or minimization.
        :type target: str, 'max' or 'min'

        :param ksi0: Initial selective pressure adjustment value, default value
                     is 2
        :type ksi0: float

        :param r: The reduction factor for selective pressure adjustment value,
                  ksi^(k-1)*r is the adjustment value for generation k, default
                  value is 0.9
        :type r: float in range [0.9, 0.999]

        Dynamic Linear Scaling:
            For maximizaiton, f' = f(x) - min{f(x)} + ksi^k, k is generation number.
        '''
        def _dynamic_linear_scaling(fn):
            # For original fitness calculation.
            self.ori_fitness = fn

            @wraps(fn)
            def _fn_with_dynamic_linear_scaling(indv):
                f = fn(indv)
                k = self.current_generation + 1

                if target == 'max':
                    f_prime = f - self.ori_fmin + ksi0*(r**k)
                elif target == 'min':
                    f_prime = self.ori_fmax - f + ksi0*(r**k)
                else:
                    raise ValueError('Invalid target type({})'.format(target))
                return f_prime

            return _fn_with_dynamic_linear_scaling

        return _dynamic_linear_scaling

    def minimize(self, fn):
        '''
        A decorator for minimizing the fitness function.
        '''
        @wraps(fn)
        def _minimize(indv):
            return -fn(indv)
        return _minimize
